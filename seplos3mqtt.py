#!/usr/bin/env python

"""
Seplos BMSv3 to MQTT
---------------------------------------------------------------------------
Changelog:
  - Initial version: basic PIA, PIB, PIC decoding
  - Added temperature decoding - not publishing probes 5-8
  - Added range validation - out of range values are not published to MQTT
  - Added MQTT publish throttling (cache + flush, every 2 seconds)
  - Added unknown frame analyser (logs to seplos3mqtt_unknown.log)
  - Full register map decode based on official Seplos BMS v3 spec:
      PIA (0x1000): All 18 registers including system events + extern voltage
      PIB (0x1100): All 26 registers including cell temps 1-8 + ambient + power
      PIC (0x1200): All 18 bytes fully decoded with meaningful names:
                    per-cell low/high voltage alarms, per-cell temp alarms,
                    per-cell balancing, mode flags, named alarm/protection flags,
                    FET states, hardware failure flags
      SPA (0x1300): Settings/thresholds block (106 registers, published once)
      SFA (0x1400): Feature enable/disable flags (80 bits, published once)
"""

# --------------------------------------------------------------------------- #
# import the various needed libraries
# --------------------------------------------------------------------------- #
import signal
import sys
import logging
import serial
import configparser
import paho.mqtt.client as mqtt
import os
import time

# --------------------------------------------------------------------------- #
# configure the logging system
# --------------------------------------------------------------------------- #
class myFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.INFO:
            self._style._fmt = "%(asctime)-15s %(message)s"
        elif record.levelno == logging.DEBUG:
            self._style._fmt = f"%(asctime)-15s \033[36m%(levelname)-8s\033[0m: %(message)s"
        else:
            color = {
                logging.WARNING: 33,
                logging.ERROR: 31,
                logging.FATAL: 31,
            }.get(record.levelno, 0)
            self._style._fmt = f"%(asctime)-15s \033[{color}m%(levelname)-8s %(threadName)-15s-%(module)-15s:%(lineno)-8s\033[0m: %(message)s"
        return super().format(record)

log = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(myFormatter())
log.setLevel(logging.INFO)
log.addHandler(handler)

# --------------------------------------------------------------------------- #
# declare the sniffer
# --------------------------------------------------------------------------- #
class SerialSnooper:

    def __init__(self, port, mqtt_server, mqtt_port, mqtt_user, mqtt_pass):
        self.port = port
        self.data = bytearray(0)
        self.trashdata = False
        self.trashdataf = bytearray(0)
        self.unknown_frame_buf = bytearray(0)   # accumulates bytes that don't match known frames
        self.batts_declared_set = set()
        # Cache of topic -> value, flushed to MQTT every publish_interval seconds
        self.mqtt_cache = {}
        self.last_publish_time = 0.0
        self.publish_interval = 2.0             # seconds between MQTT publishes
        # init the signal handler for a clean exit
        signal.signal(signal.SIGINT, self.signal_handler)

        log.info(f"Opening serial interface, port: {port} 19200 8N1 timeout: 0.001750")
        self.connection = serial.Serial(
            port=port, baudrate=19200,
            bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE, timeout=0.001750)
        log.debug(self.connection)

        self.mqtt_hass = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.mqtt_hass.username_pw_set(username=mqtt_user, password=mqtt_pass)
        try:
            log.info(f"Opening MQTT connection, server: {mqtt_server}\tport: {mqtt_port}")
            self.mqtt_hass.connect(mqtt_server, mqtt_port)
        except ConnectionRefusedError:
            print("Error: Unable to connect to MQTT server.")
        except Exception as e:
            print(f"MQTT Unexpected error: {str(e)}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def open(self):
        self.connection.open()

    def close(self):
        self.connection.close()

    def read_raw(self, n=1):
        return self.connection.read(n)

    # --------------------------------------------------------------------------- #
    # configure a clean exit
    # --------------------------------------------------------------------------- #
    def signal_handler(self, sig, frame):
        for batt_number in self.batts_declared_set:
            log.info(f"Sending offline signal for Battery {batt_number}")
            self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{batt_number}/state", "offline", retain=True)
        print('\nGoodbye\n')
        sys.exit(0)

    def to_lower_under(self, text):
        text = text.lower()
        text = text.replace(' ', '_')
        return text

    # --------------------------------------------------------------------------- #
    # Range validation helper
    # --------------------------------------------------------------------------- #
    def is_valid(self, value, min_val, max_val, label="value"):
        if min_val <= value <= max_val:
            return True
        log.warning(f"Out of range: {label} = {value} (expected {min_val} to {max_val}) — not published")
        return False

    # --------------------------------------------------------------------------- #
    # Cache a value for deferred MQTT publishing
    # --------------------------------------------------------------------------- #
    def cache_value(self, topic, value, retain=True):
        self.mqtt_cache[topic] = (value, retain)

    # --------------------------------------------------------------------------- #
    # Flush the cache to MQTT if the publish interval has elapsed
    # --------------------------------------------------------------------------- #
    def flush_cache(self):
        now = time.time()
        if now - self.last_publish_time >= self.publish_interval:
            for topic, (value, retain) in self.mqtt_cache.items():
                self.mqtt_hass.publish(topic, value, retain=retain)
            self.last_publish_time = now
            # Unknown frame analyser - uncomment to re-enable logging to seplos3mqtt_unknown.log
            # if len(self.unknown_frame_buf) > 0:
            #     self.analyse_unknown_frame(self.unknown_frame_buf)
            #     self.unknown_frame_buf = bytearray(0)

    # --------------------------------------------------------------------------- #
    # Analyse unknown frames - log raw bytes + attempt Modbus request decode + CRC
    # --------------------------------------------------------------------------- #
    def analyse_unknown_frame(self, frame):
        hex_str = " ".join(f"{b:02x}" for b in frame)
        length = len(frame)
        lines = []
        lines.append(f"UNKNOWN [{length} bytes]: {hex_str}")

        found_valid = False
        for offset in range(len(frame)):
            remaining = frame[offset:]
            # Try as Modbus request (8 bytes)
            if len(remaining) >= 8:
                uid  = remaining[0]
                fc   = remaining[1]
                addr = (remaining[2] << 8) | remaining[3]
                qty  = (remaining[4] << 8) | remaining[5]
                crc_in_frame = (remaining[6] << 8) | remaining[7]
                crc_calc = self.calcCRC16(remaining, 6)
                if crc_in_frame == crc_calc:
                    fc_names = {
                        1: "Read Coils", 2: "Read Discrete Inputs",
                        3: "Read Holding Registers", 4: "Read Input Registers",
                        5: "Write Single Coil", 6: "Write Single Register",
                        15: "Write Multiple Coils", 16: "Write Multiple Registers"}
                    fc_name = fc_names.get(fc, f"FC{fc:#04x}")
                    lines.append(f"  -> Valid Modbus REQUEST at offset {offset}: "
                                 f"Unit={uid} {fc_name} Addr={addr:#06x}({addr}) Qty={qty} CRC=OK")
                    found_valid = True
            # Try as Modbus exception response (5 bytes)
            if len(remaining) >= 5:
                uid = remaining[0]
                fc  = remaining[1]
                err = remaining[2]
                if fc & 0x80:
                    crc_in_frame = (remaining[3] << 8) | remaining[4]
                    crc_calc = self.calcCRC16(remaining, 3)
                    if crc_in_frame == crc_calc:
                        lines.append(f"  -> Valid Modbus EXCEPTION at offset {offset}: "
                                     f"Unit={uid} FC={fc:#04x} Error={err:#04x} CRC=OK")
                        found_valid = True

        if not found_valid:
            lines.append(f"  -> No valid Modbus frames found (likely line noise or partial frame)")

        full_entry = "\n".join(lines)
        log.info(full_entry)
        try:
            with open("seplos3mqtt_unknown.log", "a") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {full_entry}\n\n")
        except Exception as e:
            log.warning(f"Could not write to unknown frame log: {e}")

    # --------------------------------------------------------------------------- #
    # Bufferise the data and call the decoder on interframe timeout
    # --------------------------------------------------------------------------- #
    def process_data(self, data):
        if len(data) <= 0:
            if len(self.data) > 2:
                self.data = self.decodeModbus(self.data)
            return
        for dat in data:
            self.data.append(dat)

    # --------------------------------------------------------------------------- #
    # Home Assistant autodiscovery - sensor
    # --------------------------------------------------------------------------- #
    def autodiscovery_sensor(self, dev_cla, state_class, sensor_unit, sensor_name, batt_number):
        name_under = self.to_lower_under(sensor_name)
        dev_cla_str    = f""" "dev_cla": "{dev_cla}", """    if dev_cla    else ""
        state_cls_str  = f""" "stat_cla": "{state_class}", """ if state_class else ""
        unit_str       = f""" "unit_of_meas": "{sensor_unit}", """ if sensor_unit else ""

        mqtt_packet = f"""
            {{
                "name": "{sensor_name}",
                "stat_t": "{mqtt_prefix}/battery_{batt_number}/{name_under}",
                "avty_t": "{mqtt_prefix}/battery_{batt_number}/state",
                "uniq_id": "seplos_battery_{batt_number}_{name_under}",
                {dev_cla_str}
                {unit_str}
                {state_cls_str}
                "dev": {{
                    "ids": "seplos_battery_{batt_number}",
                    "name": "Seplos BMS {batt_number}",
                    "sw": "seplos3mqtt 1.0",
                    "mdl": "Seplos BMSv3 MQTT",
                    "mf": "Domotica Solar"
                }},
                "origin": {{
                    "name": "seplos3mqtt by Domotica Solar",
                    "sw": "1.0",
                    "url": "https://domotica.solar/"
                }}
            }}"""
        self.mqtt_hass.publish(
            f"homeassistant/sensor/seplos_bms_{batt_number}/{name_under}/config",
            mqtt_packet, retain=True)

    # --------------------------------------------------------------------------- #
    # Home Assistant autodiscovery - binary sensor (for alarm/status bits)
    # --------------------------------------------------------------------------- #
    def autodiscovery_binary_sensor(self, sensor_name, batt_number, device_class=""):
        name_under = self.to_lower_under(sensor_name)
        dev_cla_str = f""" "dev_cla": "{device_class}", """ if device_class else ""

        mqtt_packet = f"""
            {{
                "name": "{sensor_name}",
                "stat_t": "{mqtt_prefix}/battery_{batt_number}/{name_under}",
                "avty_t": "{mqtt_prefix}/battery_{batt_number}/state",
                "uniq_id": "seplos_battery_{batt_number}_{name_under}",
                "payload_on": "1",
                "payload_off": "0",
                {dev_cla_str}
                "dev": {{
                    "ids": "seplos_battery_{batt_number}",
                    "name": "Seplos BMS {batt_number}",
                    "sw": "seplos3mqtt 1.0",
                    "mdl": "Seplos BMSv3 MQTT",
                    "mf": "Domotica Solar"
                }},
                "origin": {{
                    "name": "seplos3mqtt by Domotica Solar",
                    "sw": "1.0",
                    "url": "https://domotica.solar/"
                }}
            }}"""
        self.mqtt_hass.publish(
            f"homeassistant/binary_sensor/seplos_bms_{batt_number}/{name_under}/config",
            mqtt_packet, retain=True)

    # --------------------------------------------------------------------------- #
    # Register all sensors for a battery with Home Assistant
    # --------------------------------------------------------------------------- #
    def autodiscovery_battery(self, unitIdentifier):
        log.info(f"Sending autodiscovery block Battery {unitIdentifier}")
        b = unitIdentifier

        # --- PIA: Pack main sensors ---
        self.autodiscovery_sensor("voltage",     "measurement", "V",      "Pack Voltage",             b)
        self.autodiscovery_sensor("current",     "measurement", "A",      "Current",                  b)
        self.autodiscovery_sensor("",            "measurement", "Ah",     "Remaining Capacity",       b)
        self.autodiscovery_sensor("",            "measurement", "Ah",     "Total Capacity",           b)
        self.autodiscovery_sensor("",            "measurement", "Ah",     "Total Discharge Capacity", b)
        self.autodiscovery_sensor("",            "measurement", "%",      "SOC",                      b)
        self.autodiscovery_sensor("",            "measurement", "%",      "SOH",                      b)
        self.autodiscovery_sensor("",            "measurement", "cycles", "Cycles",                   b)
        self.autodiscovery_sensor("voltage",     "measurement", "V",      "Average Cell Voltage",     b)
        self.autodiscovery_sensor("temperature", "measurement", "°C",     "Average Cell Temp",        b)
        self.autodiscovery_sensor("voltage",     "measurement", "V",      "Max Cell Voltage",         b)
        self.autodiscovery_sensor("voltage",     "measurement", "V",      "Min Cell Voltage",         b)
        self.autodiscovery_sensor("temperature", "measurement", "°C",     "Max Cell Temp",            b)
        self.autodiscovery_sensor("temperature", "measurement", "°C",     "Min Cell Temp",            b)
        self.autodiscovery_sensor("",            "",            "",       "System Events",            b)
        self.autodiscovery_sensor("current",     "measurement", "A",      "Max Discharge Current",    b)
        self.autodiscovery_sensor("current",     "measurement", "A",      "Max Charge Current",       b)
        self.autodiscovery_sensor("voltage",     "measurement", "V",      "Extern Voltage",           b)
        self.autodiscovery_sensor("power",       "measurement", "W",      "Power",                    b)
        self.autodiscovery_sensor("voltage",     "measurement", "mV",     "Cell Delta",               b)

        # --- PIB: Cell voltages ---
        for i in range(1, 17):
            self.autodiscovery_sensor("voltage", "measurement", "V", f"Cell {i}", b)

        # --- PIB: Cell temperatures (1-8 + ambient + power) ---
        for i in range(1, 9):
            self.autodiscovery_sensor("temperature", "measurement", "°C", f"Cell Temperature {i}", b)
        self.autodiscovery_sensor("temperature", "measurement", "°C", "Ambient Temperature", b)
        self.autodiscovery_sensor("temperature", "measurement", "°C", "Power Temperature",   b)

        # --- PIC byte 8: Charge/discharge mode ---
        self.autodiscovery_sensor("", "", "", "Status", b)

        # --- PIC bytes 0-1: Per-cell low voltage alarms ---
        for i in range(1, 17):
            self.autodiscovery_binary_sensor(f"Cell {i} Low Voltage Alarm",  b, "problem")
        # --- PIC bytes 2-3: Per-cell high voltage alarms ---
        for i in range(1, 17):
            self.autodiscovery_binary_sensor(f"Cell {i} High Voltage Alarm", b, "problem")
        # --- PIC bytes 4-5: Per-cell temp alarms ---
        for i in range(1, 9):
            self.autodiscovery_binary_sensor(f"Cell Temp {i} Low Alarm",  b, "problem")
        for i in range(1, 9):
            self.autodiscovery_binary_sensor(f"Cell Temp {i} High Alarm", b, "problem")
        # --- PIC bytes 6-7: Per-cell balancing ---
        for i in range(1, 17):
            self.autodiscovery_binary_sensor(f"Cell {i} Balancing", b)

        # --- PIC byte 9: Cell/pack voltage alarms ---
        self.autodiscovery_binary_sensor("Cell High Voltage Alarm",       b, "problem")
        self.autodiscovery_binary_sensor("Cell Over Voltage Protection",  b, "problem")
        self.autodiscovery_binary_sensor("Cell Low Voltage Alarm",        b, "problem")
        self.autodiscovery_binary_sensor("Cell Under Voltage Protection", b, "problem")
        self.autodiscovery_binary_sensor("Pack High Voltage Alarm",       b, "problem")
        self.autodiscovery_binary_sensor("Pack Over Voltage Protection",  b, "problem")
        self.autodiscovery_binary_sensor("Pack Low Voltage Alarm",        b, "problem")
        self.autodiscovery_binary_sensor("Pack Under Voltage Protection", b, "problem")

        # --- PIC byte 10: Charge temperature alarms ---
        self.autodiscovery_binary_sensor("Charge High Temp Alarm",        b, "problem")
        self.autodiscovery_binary_sensor("Charge Over Temp Protection",   b, "problem")
        self.autodiscovery_binary_sensor("Charge Low Temp Alarm",         b, "problem")
        self.autodiscovery_binary_sensor("Charge Under Temp Protection",  b, "problem")
        # --- PIC byte 10: Discharge temperature alarms ---
        self.autodiscovery_binary_sensor("Discharge High Temp Alarm",     b, "problem")
        self.autodiscovery_binary_sensor("Discharge Over Temp Protection",b, "problem")
        self.autodiscovery_binary_sensor("Discharge Low Temp Alarm",      b, "problem")
        self.autodiscovery_binary_sensor("Discharge Under Temp Protection",b,"problem")

        # --- PIC byte 11: Ambient + power temp alarms ---
        self.autodiscovery_binary_sensor("Ambient High Temp Alarm",       b, "problem")
        self.autodiscovery_binary_sensor("Ambient Over Temp Protection",  b, "problem")
        self.autodiscovery_binary_sensor("Ambient Low Temp Alarm",        b, "problem")
        self.autodiscovery_binary_sensor("Ambient Under Temp Protection", b, "problem")
        self.autodiscovery_binary_sensor("Power High Temp Alarm",         b, "problem")
        self.autodiscovery_binary_sensor("Power Over Temp Protection",    b, "problem")
        self.autodiscovery_binary_sensor("Cell Low Temp Heating",         b)

        # --- PIC byte 12: Current alarms ---
        self.autodiscovery_binary_sensor("Charge Current Alarm",                    b, "problem")
        self.autodiscovery_binary_sensor("Charge Over Current Protection",          b, "problem")
        self.autodiscovery_binary_sensor("Charge Over Current Secondary Protection",b, "problem")
        self.autodiscovery_binary_sensor("Discharge Current Alarm",                 b, "problem")
        self.autodiscovery_binary_sensor("Discharge Over Current Protection",       b, "problem")
        self.autodiscovery_binary_sensor("Discharge Over Current Secondary Protection", b, "problem")
        self.autodiscovery_binary_sensor("Output Short Circuit Protection",         b, "problem")

        # --- PIC byte 13: Lock states ---
        self.autodiscovery_binary_sensor("Output Short Circuit Lock",               b, "problem")
        self.autodiscovery_binary_sensor("Charge Over Current Secondary Lock",      b, "problem")
        self.autodiscovery_binary_sensor("Discharge Over Current Secondary Lock",   b, "problem")
        self.autodiscovery_binary_sensor("Zero Point Uncalibrated",                 b, "problem")

        # --- PIC byte 14: SOC alarms + cell diff ---
        self.autodiscovery_binary_sensor("SOC Alarm",       b, "problem")
        self.autodiscovery_binary_sensor("SOC Protection",  b, "problem")
        self.autodiscovery_binary_sensor("Cell Diff Alarm", b, "problem")

        # --- PIC byte 15: FET states ---
        self.autodiscovery_binary_sensor("Discharge FET On",      b)
        self.autodiscovery_binary_sensor("Charge FET On",         b)
        self.autodiscovery_binary_sensor("Current Limit FET On",  b)
        self.autodiscovery_binary_sensor("Temp Regulate FET On",  b)

        # --- PIC byte 16: Balancing module + cell failure ---
        self.autodiscovery_binary_sensor("Balancing Module On",      b)
        self.autodiscovery_binary_sensor("Static Balancing Active",  b)
        self.autodiscovery_binary_sensor("Static Balancing Timeout", b, "problem")
        self.autodiscovery_binary_sensor("Balancing Temp Limited",   b)
        self.autodiscovery_binary_sensor("Cell Failure Alarm",       b, "problem")

        # --- PIC byte 17: Hardware failures ---
        self.autodiscovery_binary_sensor("NTC Failure",               b, "problem")
        self.autodiscovery_binary_sensor("AFE Failure",               b, "problem")
        self.autodiscovery_binary_sensor("Charge Mosfet Failure",     b, "problem")
        self.autodiscovery_binary_sensor("Discharge Mosfet Failure",  b, "problem")
        self.autodiscovery_binary_sensor("Cell Diff Failure",         b, "problem")
        self.autodiscovery_binary_sensor("Aerosol Alarm",             b, "problem")

        log.info(f"Sending online signal for Battery {unitIdentifier}")
        self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/state", "online", retain=True)

    # --------------------------------------------------------------------------- #
    # Decode Kelvin-offset temperature (used in PIB and PIA)
    # Raw value is in tenths of Kelvin (e.g. 2981 = 298.1K = 25.0°C)
    # --------------------------------------------------------------------------- #
    def decode_temp(self, raw):
        return round((raw / 10.0) - 273.15, 1)

    # --------------------------------------------------------------------------- #
    # Publish a single bit from a byte as a binary sensor value (0 or 1)
    # --------------------------------------------------------------------------- #
    def publish_bit(self, byte_val, bit_index, topic):
        self.cache_value(topic, (byte_val >> bit_index) & 1)

    # --------------------------------------------------------------------------- #
    # Debuffer and decode the Modbus frames
    # --------------------------------------------------------------------------- #
    def decodeModbus(self, data):
        modbusdata = data
        bufferIndex = 0

        while True:
            unitIdentifier = 0
            functionCode   = 0
            readByteCount  = 0
            readData       = bytearray(0)
            crc16          = 0
            responce       = False
            needMoreData   = False
            frameStartIndex = bufferIndex

            if len(modbusdata) > (frameStartIndex + 2):
                unitIdentifier = modbusdata[bufferIndex]; bufferIndex += 1
                functionCode   = modbusdata[bufferIndex]; bufferIndex += 1

                # ----------------------------------------------------------------
                # FC01 - Read Coils  (PIC: 0x1200, 144 bits = 18 bytes)
                # ----------------------------------------------------------------
                if functionCode == 1:
                    expectedLenght = 7
                    if len(modbusdata) >= (frameStartIndex + expectedLenght):
                        bufferIndex = frameStartIndex + 2
                        readByteCount = modbusdata[bufferIndex]; bufferIndex += 1
                        expectedLenght = 5 + readByteCount
                        if len(modbusdata) >= (frameStartIndex + expectedLenght):
                            for _ in range(readByteCount):
                                readData.append(modbusdata[bufferIndex]); bufferIndex += 1
                            crc16    = (modbusdata[bufferIndex] * 0x0100) + modbusdata[bufferIndex + 1]
                            metCRC16 = self.calcCRC16(modbusdata, bufferIndex)
                            bufferIndex += 2
                            if crc16 == metCRC16:
                                if self.trashdata:
                                    self.trashdata = False
                                    self.trashdataf += "]"
                                    log.info(f"Trashed data, {self.trashdataf}")
                                responce = True

                                # PIC block: 18 bytes = 144 bits
                                if readByteCount == 18:
                                    if unitIdentifier not in self.batts_declared_set:
                                        self.autodiscovery_battery(unitIdentifier)
                                        self.batts_declared_set.add(unitIdentifier)

                                    b = unitIdentifier
                                    p = f"{mqtt_prefix}/battery_{b}"

                                    # --- Byte 0-1: Per-cell LOW voltage alarms (cells 1-16) ---
                                    for i in range(8):
                                        self.publish_bit(readData[0], i, f"{p}/cell_{i+1}_low_voltage_alarm")
                                    for i in range(8):
                                        self.publish_bit(readData[1], i, f"{p}/cell_{i+9}_low_voltage_alarm")

                                    # --- Byte 2-3: Per-cell HIGH voltage alarms (cells 1-16) ---
                                    for i in range(8):
                                        self.publish_bit(readData[2], i, f"{p}/cell_{i+1}_high_voltage_alarm")
                                    for i in range(8):
                                        self.publish_bit(readData[3], i, f"{p}/cell_{i+9}_high_voltage_alarm")

                                    # --- Byte 4: Per-cell temp LOW alarms (sensors 1-8) ---
                                    for i in range(8):
                                        self.publish_bit(readData[4], i, f"{p}/cell_temp_{i+1}_low_alarm")

                                    # --- Byte 5: Per-cell temp HIGH alarms (sensors 1-8) ---
                                    for i in range(8):
                                        self.publish_bit(readData[5], i, f"{p}/cell_temp_{i+1}_high_alarm")

                                    # --- Byte 6-7: Per-cell balancing active (cells 1-16) ---
                                    for i in range(8):
                                        self.publish_bit(readData[6], i, f"{p}/cell_{i+1}_balancing")
                                    for i in range(8):
                                        self.publish_bit(readData[7], i, f"{p}/cell_{i+9}_balancing")

                                    # --- Byte 8: Charge/discharge mode ---
                                    strStatus = ""
                                    if   (readData[8] >> 0) & 1: strStatus = "Discharge"
                                    elif (readData[8] >> 1) & 1: strStatus = "Charge"
                                    elif (readData[8] >> 2) & 1: strStatus = "Floating charge"
                                    elif (readData[8] >> 3) & 1: strStatus = "Full charge"
                                    elif (readData[8] >> 4) & 1: strStatus = "Standby mode"
                                    elif (readData[8] >> 5) & 1: strStatus = "Turn off"
                                    if strStatus:
                                        self.cache_value(f"{p}/status", strStatus)

                                    # --- Byte 9: Cell/pack voltage alarms ---
                                    self.publish_bit(readData[9], 0, f"{p}/cell_high_voltage_alarm")
                                    self.publish_bit(readData[9], 1, f"{p}/cell_over_voltage_protection")
                                    self.publish_bit(readData[9], 2, f"{p}/cell_low_voltage_alarm")
                                    self.publish_bit(readData[9], 3, f"{p}/cell_under_voltage_protection")
                                    self.publish_bit(readData[9], 4, f"{p}/pack_high_voltage_alarm")
                                    self.publish_bit(readData[9], 5, f"{p}/pack_over_voltage_protection")
                                    self.publish_bit(readData[9], 6, f"{p}/pack_low_voltage_alarm")
                                    self.publish_bit(readData[9], 7, f"{p}/pack_under_voltage_protection")

                                    # --- Byte 10: Charge temp alarms (bits 0-3) + Discharge temp alarms (bits 4-7) ---
                                    self.publish_bit(readData[10], 0, f"{p}/charge_high_temp_alarm")
                                    self.publish_bit(readData[10], 1, f"{p}/charge_over_temp_protection")
                                    self.publish_bit(readData[10], 2, f"{p}/charge_low_temp_alarm")
                                    self.publish_bit(readData[10], 3, f"{p}/charge_under_temp_protection")
                                    self.publish_bit(readData[10], 4, f"{p}/discharge_high_temp_alarm")
                                    self.publish_bit(readData[10], 5, f"{p}/discharge_over_temp_protection")
                                    self.publish_bit(readData[10], 6, f"{p}/discharge_low_temp_alarm")
                                    self.publish_bit(readData[10], 7, f"{p}/discharge_under_temp_protection")

                                    # --- Byte 11: Ambient + power temp alarms ---
                                    self.publish_bit(readData[11], 0, f"{p}/ambient_high_temp_alarm")
                                    self.publish_bit(readData[11], 1, f"{p}/ambient_over_temp_protection")
                                    self.publish_bit(readData[11], 2, f"{p}/ambient_low_temp_alarm")
                                    self.publish_bit(readData[11], 3, f"{p}/ambient_under_temp_protection")
                                    self.publish_bit(readData[11], 4, f"{p}/power_high_temp_alarm")
                                    self.publish_bit(readData[11], 5, f"{p}/power_over_temp_protection")
                                    self.publish_bit(readData[11], 6, f"{p}/cell_low_temp_heating")

                                    # --- Byte 12: Current alarms ---
                                    self.publish_bit(readData[12], 0, f"{p}/charge_current_alarm")
                                    self.publish_bit(readData[12], 1, f"{p}/charge_over_current_protection")
                                    self.publish_bit(readData[12], 2, f"{p}/charge_over_current_secondary_protection")
                                    self.publish_bit(readData[12], 3, f"{p}/discharge_current_alarm")
                                    self.publish_bit(readData[12], 4, f"{p}/discharge_over_current_protection")
                                    self.publish_bit(readData[12], 5, f"{p}/discharge_over_current_secondary_protection")
                                    self.publish_bit(readData[12], 6, f"{p}/output_short_circuit_protection")

                                    # --- Byte 13: Lock states ---
                                    self.publish_bit(readData[13], 0, f"{p}/output_short_circuit_lock")
                                    self.publish_bit(readData[13], 2, f"{p}/charge_over_current_secondary_lock")
                                    self.publish_bit(readData[13], 3, f"{p}/discharge_over_current_secondary_lock")
                                    self.publish_bit(readData[13], 6, f"{p}/zero_point_uncalibrated")

                                    # --- Byte 14: SOC alarms + cell diff ---
                                    self.publish_bit(readData[14], 2, f"{p}/soc_alarm")
                                    self.publish_bit(readData[14], 3, f"{p}/soc_protection")
                                    self.publish_bit(readData[14], 4, f"{p}/cell_diff_alarm")

                                    # --- Byte 15: FET states ---
                                    self.publish_bit(readData[15], 0, f"{p}/discharge_fet_on")
                                    self.publish_bit(readData[15], 1, f"{p}/charge_fet_on")
                                    self.publish_bit(readData[15], 2, f"{p}/current_limit_fet_on")
                                    self.publish_bit(readData[15], 3, f"{p}/temp_regulate_fet_on")

                                    # --- Byte 16: Balancing module + cell failure ---
                                    self.publish_bit(readData[16], 0, f"{p}/balancing_module_on")
                                    self.publish_bit(readData[16], 1, f"{p}/static_balancing_active")
                                    self.publish_bit(readData[16], 2, f"{p}/static_balancing_timeout")
                                    self.publish_bit(readData[16], 3, f"{p}/balancing_temp_limited")
                                    self.publish_bit(readData[16], 4, f"{p}/cell_failure_alarm")

                                    # --- Byte 17: Hardware failures ---
                                    self.publish_bit(readData[17], 0, f"{p}/ntc_failure")
                                    self.publish_bit(readData[17], 1, f"{p}/afe_failure")
                                    self.publish_bit(readData[17], 2, f"{p}/charge_mosfet_failure")
                                    self.publish_bit(readData[17], 3, f"{p}/discharge_mosfet_failure")
                                    self.publish_bit(readData[17], 4, f"{p}/cell_diff_failure")
                                    self.publish_bit(readData[17], 7, f"{p}/aerosol_alarm")

                                # SFA block: 10 bytes = 80 bits (feature enable/disable flags)
                                # Published once as config — these are static BMS settings
                                elif readByteCount == 10:
                                    if unitIdentifier not in self.batts_declared_set:
                                        self.autodiscovery_battery(unitIdentifier)
                                        self.batts_declared_set.add(unitIdentifier)
                                    self.decode_SFA(unitIdentifier, readData)

                                modbusdata = modbusdata[bufferIndex:]
                                bufferIndex = 0
                        else:
                            needMoreData = True
                    else:
                        needMoreData = True

                # ----------------------------------------------------------------
                # FC04 - Read Input Registers  (PIA: 0x1000, PIB: 0x1100, SPA: 0x1300)
                # ----------------------------------------------------------------
                elif functionCode == 4:
                    expectedLenght = 7
                    if len(modbusdata) >= (frameStartIndex + expectedLenght):
                        bufferIndex = frameStartIndex + 2
                        readByteCount = modbusdata[bufferIndex]; bufferIndex += 1
                        expectedLenght = 5 + readByteCount
                        if len(modbusdata) >= (frameStartIndex + expectedLenght):
                            for _ in range(readByteCount):
                                readData.append(modbusdata[bufferIndex]); bufferIndex += 1
                            crc16    = (modbusdata[bufferIndex] * 0x0100) + modbusdata[bufferIndex + 1]
                            metCRC16 = self.calcCRC16(modbusdata, bufferIndex)
                            bufferIndex += 2
                            if crc16 == metCRC16:
                                if self.trashdata:
                                    self.trashdata = False
                                    self.trashdataf += "]"
                                responce = True

                                if unitIdentifier not in self.batts_declared_set:
                                    self.autodiscovery_battery(unitIdentifier)
                                    self.batts_declared_set.add(unitIdentifier)

                                # PIB: 52 bytes = 26 registers (cell voltages + temperatures)
                                if readByteCount == 52:
                                    self.decode_PIB(unitIdentifier, readData)

                                # PIA: 36 bytes = 18 registers (pack main info)
                                elif readByteCount == 36:
                                    self.decode_PIA(unitIdentifier, readData)

                                # SPA: 212 bytes = 106 registers (settings/thresholds)
                                elif readByteCount == 212:
                                    self.decode_SPA(unitIdentifier, readData)

                                modbusdata = modbusdata[bufferIndex:]
                                bufferIndex = 0
                        else:
                            needMoreData = True
                    else:
                        needMoreData = True
            else:
                needMoreData = True

            if needMoreData:
                return modbusdata
            elif responce == False:
                self.unknown_frame_buf.append(modbusdata[frameStartIndex])
                if self.trashdata:
                    self.trashdataf += " {:02x}".format(modbusdata[frameStartIndex])
                else:
                    self.trashdata = True
                    self.trashdataf = "Ignoring data: [{:02x}".format(modbusdata[frameStartIndex])
                bufferIndex = frameStartIndex + 1
                modbusdata = modbusdata[bufferIndex:]
                bufferIndex = 0

    # --------------------------------------------------------------------------- #
    # Decode PIA (0x1000): Pack main information - 18 registers / 36 bytes
    # --------------------------------------------------------------------------- #
    def decode_PIA(self, b, d):
        p = f"{mqtt_prefix}/battery_{b}"
        rn = []
        for i in range(0, 36, 2):
            rn.append((d[i] << 8) | d[i + 1])

        # Pack Voltage (reg 1000): scale 0.01, range 40-60V
        pack_voltage = rn[0] / 100.0
        if self.is_valid(pack_voltage, 40.0, 60.0, f"batt {b} pack_voltage"):
            self.cache_value(f"{p}/pack_voltage", pack_voltage)

        # Current (reg 1001): scale 0.01, signed, range -500 to 500A
        current_raw = rn[1] if rn[1] <= 32767 else rn[1] - 65536
        current = current_raw / 100.0
        if self.is_valid(current, -500.0, 500.0, f"batt {b} current"):
            self.cache_value(f"{p}/current", current)

        # Remaining Capacity (reg 1002): scale 0.01, range 0-10000Ah
        remaining_cap = rn[2] / 100.0
        if self.is_valid(remaining_cap, 0.0, 10000.0, f"batt {b} remaining_capacity"):
            self.cache_value(f"{p}/remaining_capacity", remaining_cap)

        # Total Capacity (reg 1003): scale 0.01, range 0-10000Ah
        total_cap = rn[3] / 100.0
        if self.is_valid(total_cap, 0.0, 10000.0, f"batt {b} total_capacity"):
            self.cache_value(f"{p}/total_capacity", total_cap)

        # Total Discharge Capacity (reg 1004): scale 10
        total_dis_cap = rn[4] * 10
        if self.is_valid(total_dis_cap, 0, 100000000, f"batt {b} total_discharge_capacity"):
            self.cache_value(f"{p}/total_discharge_capacity", total_dis_cap)

        # SOC (reg 1005): scale 0.1, range 0-100%
        soc = rn[5] / 10.0
        if self.is_valid(soc, 0.0, 100.0, f"batt {b} soc"):
            self.cache_value(f"{p}/soc", soc)

        # SOH (reg 1006): scale 0.1, range 0-100%
        soh = rn[6] / 10.0
        if self.is_valid(soh, 0.0, 100.0, f"batt {b} soh"):
            self.cache_value(f"{p}/soh", soh)

        # Cycles (reg 1007): scale 1, range 0-20000
        cycles = rn[7]
        if self.is_valid(cycles, 0, 20000, f"batt {b} cycles"):
            self.cache_value(f"{p}/cycles", cycles)

        # Average Cell Voltage (reg 1008): scale 0.001, range 2.5-3.65V
        avg_cell_v = rn[8] / 1000.0
        if self.is_valid(avg_cell_v, 2.5, 3.65, f"batt {b} average_cell_voltage"):
            self.cache_value(f"{p}/average_cell_voltage", avg_cell_v)

        # Average Cell Temp (reg 1009): Kelvin*10 offset, range -20 to 80°C
        avg_cell_temp = self.decode_temp(rn[9])
        if self.is_valid(avg_cell_temp, -20.0, 80.0, f"batt {b} average_cell_temp"):
            self.cache_value(f"{p}/average_cell_temp", avg_cell_temp)

        # Max Cell Voltage (reg 100A): scale 0.001, range 2.5-3.65V
        max_cell_v = rn[10] / 1000.0
        if self.is_valid(max_cell_v, 2.5, 3.65, f"batt {b} max_cell_voltage"):
            self.cache_value(f"{p}/max_cell_voltage", max_cell_v)

        # Min Cell Voltage (reg 100B): scale 0.001, range 2.5-3.65V
        min_cell_v = rn[11] / 1000.0
        if self.is_valid(min_cell_v, 2.5, 3.65, f"batt {b} min_cell_voltage"):
            self.cache_value(f"{p}/min_cell_voltage", min_cell_v)

        # Max Cell Temp (reg 100C): Kelvin*10 offset, range -20 to 80°C
        max_cell_temp = self.decode_temp(rn[12])
        if self.is_valid(max_cell_temp, -20.0, 80.0, f"batt {b} max_cell_temp"):
            self.cache_value(f"{p}/max_cell_temp", max_cell_temp)

        # Min Cell Temp (reg 100D): Kelvin*10 offset, range -20 to 80°C
        min_cell_temp = self.decode_temp(rn[13])
        if self.is_valid(min_cell_temp, -20.0, 80.0, f"batt {b} min_cell_temp"):
            self.cache_value(f"{p}/min_cell_temp", min_cell_temp)

        # System Events (reg 100E): raw bitmask - publish as-is
        self.cache_value(f"{p}/system_events", rn[14])

        # Max Discharge Current (reg 100F): scale 1, range 0-500A
        max_dis_curt = rn[15]
        if self.is_valid(max_dis_curt, 0, 500, f"batt {b} max_discharge_current"):
            self.cache_value(f"{p}/max_discharge_current", max_dis_curt)

        # Max Charge Current (reg 1010): scale 1, range 0-500A
        max_chg_curt = rn[16]
        if self.is_valid(max_chg_curt, 0, 500, f"batt {b} max_charge_current"):
            self.cache_value(f"{p}/max_charge_current", max_chg_curt)

        # Extern Voltage (reg 1011): scale 0.001, range 0-60V
        extern_v = rn[17] / 1000.0
        if self.is_valid(extern_v, 0.0, 60.0, f"batt {b} extern_voltage"):
            self.cache_value(f"{p}/extern_voltage", extern_v)

        # Calculated Power: only if current and voltage are valid
        if self.is_valid(current, -500.0, 500.0, "current (power)") and \
           self.is_valid(pack_voltage, 40.0, 60.0, "voltage (power)"):
            power = int(-current * pack_voltage)
            if self.is_valid(power, -30000, 30000, f"batt {b} power"):
                self.cache_value(f"{p}/power", power)

        # Cell Delta (mV): only if both max and min cell voltages are valid
        if self.is_valid(max_cell_v, 2.5, 3.65, "max_v (delta)") and \
           self.is_valid(min_cell_v, 2.5, 3.65, "min_v (delta)"):
            cell_delta = int(rn[10] - rn[11])
            if self.is_valid(cell_delta, 0, 1000, f"batt {b} cell_delta"):
                self.cache_value(f"{p}/cell_delta", cell_delta)

    # --------------------------------------------------------------------------- #
    # Decode PIB (0x1100): Cell voltages + temperatures - 26 registers / 52 bytes
    # --------------------------------------------------------------------------- #
    def decode_PIB(self, b, d):
        p = f"{mqtt_prefix}/battery_{b}"
        temp_var = 1

        for i in range(0, 52, 2):
            raw = (d[i] << 8) | d[i + 1]

            if i < 32:
                # Registers 1100-110F: Cell voltages 1-16, scale 0.001, range 2.5-3.65V
                celda    = raw / 1000.0
                cell_num = int(i / 2) + 1
                if self.is_valid(celda, 2.5, 3.65, f"batt {b} cell_{cell_num}"):
                    self.cache_value(f"{p}/cell_{cell_num}", celda)

            elif i < 48:
                # Registers 1110-1117: Cell temps 1-8
                # Only publish temps 1-4 — probes 5-8 not physically fitted,
                # unpopulated NTC inputs return a bogus default (e.g. 32C)
                if temp_var <= 4:
                    cell_temp = self.decode_temp(raw)
                    if self.is_valid(cell_temp, -20.0, 80.0, f"batt {b} cell_temperature_{temp_var}"):
                        self.cache_value(f"{p}/cell_temperature_{temp_var}", cell_temp)
                temp_var += 1

            elif i == 48:
                # Register 1118: Ambient temperature
                cell_temp = self.decode_temp(raw)
                if self.is_valid(cell_temp, -20.0, 80.0, f"batt {b} ambient_temperature"):
                    self.cache_value(f"{p}/ambient_temperature", cell_temp)

            elif i == 50:
                # Register 1119: Power/BMS temperature
                cell_temp = self.decode_temp(raw)
                if self.is_valid(cell_temp, -20.0, 80.0, f"batt {b} power_temperature"):
                    self.cache_value(f"{p}/power_temperature", cell_temp)

    # --------------------------------------------------------------------------- #
    # Decode SPA (0x1300): Settings/thresholds - 106 registers / 212 bytes
    # These are static config values - published with retain=True so HA keeps them
    # --------------------------------------------------------------------------- #
    def decode_SPA(self, b, d):
        p = f"{mqtt_prefix}/battery_{b}/settings"
        rn = []
        for i in range(0, 212, 2):
            rn.append((d[i] << 8) | d[i + 1])

        def signed(v):
            return v if v <= 32767 else v - 65536

        self.cache_value(f"{p}/ntc_number",                        rn[0])
        self.cache_value(f"{p}/serial_cell_count",                 rn[1])
        self.cache_value(f"{p}/pack_high_voltage_recovery",        rn[2]  / 100.0)
        self.cache_value(f"{p}/pack_high_voltage_alarm",           rn[3]  / 100.0)
        self.cache_value(f"{p}/pack_over_voltage_recovery",        rn[4]  / 100.0)
        self.cache_value(f"{p}/pack_over_voltage_protection",      rn[5]  / 100.0)
        self.cache_value(f"{p}/pack_low_voltage_recovery",         rn[6]  / 100.0)
        self.cache_value(f"{p}/pack_low_voltage_alarm",            rn[7]  / 100.0)
        self.cache_value(f"{p}/pack_under_voltage_recovery",       rn[8]  / 100.0)
        self.cache_value(f"{p}/pack_under_voltage_protection",     rn[9]  / 100.0)
        self.cache_value(f"{p}/cell_high_voltage_recovery",        rn[10] / 1000.0)
        self.cache_value(f"{p}/cell_high_voltage_alarm",           rn[11] / 1000.0)
        self.cache_value(f"{p}/cell_over_voltage_recovery",        rn[12] / 1000.0)
        self.cache_value(f"{p}/cell_over_voltage_protection",      rn[13] / 1000.0)
        self.cache_value(f"{p}/cell_low_voltage_recovery",         rn[14] / 1000.0)
        self.cache_value(f"{p}/cell_low_voltage_alarm",            rn[15] / 1000.0)
        self.cache_value(f"{p}/cell_under_voltage_recovery",       rn[16] / 1000.0)
        self.cache_value(f"{p}/cell_under_voltage_protection",     rn[17] / 1000.0)
        self.cache_value(f"{p}/cell_under_voltage_failure",        rn[18] / 1000.0)
        self.cache_value(f"{p}/cell_diff_protection",              rn[19] / 1000.0)
        self.cache_value(f"{p}/cell_diff_protection_recovery",     rn[20] / 1000.0)
        self.cache_value(f"{p}/charge_over_current_recovery",      signed(rn[21]))
        self.cache_value(f"{p}/charge_over_current_alarm",         signed(rn[22]))
        self.cache_value(f"{p}/charge_over_current_protection",    signed(rn[23]))
        self.cache_value(f"{p}/charge_over_current_delay",         rn[24] / 10.0)
        self.cache_value(f"{p}/charge_over_current2_protection",   signed(rn[25]))
        self.cache_value(f"{p}/charge_over_current2_delay_ms",     rn[26])
        self.cache_value(f"{p}/discharge_over_current_recovery",   signed(rn[27]))
        self.cache_value(f"{p}/discharge_over_current_alarm",      signed(rn[28]))
        self.cache_value(f"{p}/discharge_over_current_protection", signed(rn[29]))
        self.cache_value(f"{p}/discharge_over_current_delay",      rn[30] / 10.0)
        self.cache_value(f"{p}/discharge_over_current2_protection",signed(rn[31]))
        self.cache_value(f"{p}/discharge_over_current2_delay_ms",  rn[32])
        self.cache_value(f"{p}/short_circuit_protection",          signed(rn[33]))
        self.cache_value(f"{p}/short_circuit_delay_us",            rn[34])
        self.cache_value(f"{p}/over_current_recovery_delay",       rn[35] / 10.0)
        self.cache_value(f"{p}/over_current_lock_count",           rn[36])
        self.cache_value(f"{p}/charge_limit_duration",             rn[37] / 10.0)
        self.cache_value(f"{p}/pulse_limit_current",               rn[38])
        self.cache_value(f"{p}/pulse_limit_time",                  rn[39] / 10.0)
        self.cache_value(f"{p}/float_charge_lock_voltage",         rn[40] / 1000.0)
        self.cache_value(f"{p}/float_charge_release_voltage",      rn[41] / 1000.0)
        self.cache_value(f"{p}/float_charge_lock_current_ma",      rn[42])
        self.cache_value(f"{p}/short_circuit_precharge_rate",      rn[43] / 10.0)
        self.cache_value(f"{p}/normal_precharge_rate",             rn[44] / 10.0)
        self.cache_value(f"{p}/abnormal_precharge_rate",           rn[45] / 10.0)
        self.cache_value(f"{p}/precharge_timeout",                 rn[46] / 10.0)
        self.cache_value(f"{p}/charge_high_temp_recovery",         signed(rn[47]) / 10.0)
        self.cache_value(f"{p}/charge_high_temp_alarm",            signed(rn[48]) / 10.0)
        self.cache_value(f"{p}/charge_over_temp_recovery",         rn[49] / 10.0)
        self.cache_value(f"{p}/charge_over_temp_protection",       rn[50] / 10.0)
        self.cache_value(f"{p}/charge_low_temp_recovery",          signed(rn[51]) / 10.0)
        self.cache_value(f"{p}/charge_low_temp_alarm",             signed(rn[52]) / 10.0)
        self.cache_value(f"{p}/charge_under_temp_recovery",        signed(rn[53]) / 10.0)
        self.cache_value(f"{p}/charge_under_temp_protection",      rn[54] / 10.0)
        self.cache_value(f"{p}/discharge_high_temp_recovery",      rn[55] / 10.0)
        self.cache_value(f"{p}/discharge_high_temp_alarm",         signed(rn[56]) / 10.0)
        self.cache_value(f"{p}/discharge_over_temp_recovery",      rn[57] / 10.0)
        self.cache_value(f"{p}/discharge_over_temp_protection",    signed(rn[58]) / 10.0)
        self.cache_value(f"{p}/discharge_low_temp_recovery",       signed(rn[59]) / 10.0)
        self.cache_value(f"{p}/discharge_low_temp_alarm",          rn[60] / 10.0)
        self.cache_value(f"{p}/discharge_under_temp_recovery",     rn[61] / 10.0)
        self.cache_value(f"{p}/discharge_under_temp_protection",   rn[62] / 10.0)
        self.cache_value(f"{p}/ambient_high_temp_recovery",        rn[63] / 10.0)
        self.cache_value(f"{p}/ambient_high_temp_alarm",           rn[64] / 10.0)
        self.cache_value(f"{p}/ambient_over_temp_recovery",        rn[65] / 10.0)
        self.cache_value(f"{p}/ambient_over_temp_protection",      signed(rn[66]) / 10.0)
        self.cache_value(f"{p}/ambient_low_temp_recovery",         rn[67] / 10.0)
        self.cache_value(f"{p}/ambient_low_temp_alarm",            rn[68] / 10.0)
        self.cache_value(f"{p}/ambient_under_temp_recovery",       rn[69] / 10.0)
        self.cache_value(f"{p}/ambient_under_temp_protection",     rn[70] / 10.0)
        self.cache_value(f"{p}/power_high_temp_recovery",          rn[71] / 10.0)
        self.cache_value(f"{p}/power_high_temp_alarm",             rn[72] / 10.0)
        self.cache_value(f"{p}/power_over_temp_recovery",          rn[73] / 10.0)
        self.cache_value(f"{p}/power_over_temp_protection",        rn[74] / 10.0)
        self.cache_value(f"{p}/temp_regulate_stop",                rn[75] / 10.0)
        self.cache_value(f"{p}/temp_regulate_start",               rn[76] / 10.0)
        self.cache_value(f"{p}/balance_high_temp_limit",           rn[77] / 10.0)
        self.cache_value(f"{p}/balance_low_temp_limit",            rn[78] / 10.0)
        self.cache_value(f"{p}/static_balance_timing_h",           rn[79])
        self.cache_value(f"{p}/balance_open_voltage",              rn[80] / 1000.0)
        self.cache_value(f"{p}/balance_open_diff",                 rn[81] / 1000.0)
        self.cache_value(f"{p}/balance_stop_diff",                 rn[82] / 1000.0)
        self.cache_value(f"{p}/power_supply_soc",                  rn[83] / 10.0)
        self.cache_value(f"{p}/soc_low_recovery",                  rn[84] / 10.0)
        self.cache_value(f"{p}/soc_low_alarm",                     rn[85] / 10.0)
        self.cache_value(f"{p}/soc_protection_recovery",           rn[86] / 10.0)
        self.cache_value(f"{p}/soc_low_protection",                rn[87] / 10.0)
        self.cache_value(f"{p}/rated_capacity_ah",                 rn[88] / 100.0)
        self.cache_value(f"{p}/total_capacity_ah",                 rn[89] / 100.0)
        self.cache_value(f"{p}/remaining_capacity_ah",             rn[90] / 100.0)
        self.cache_value(f"{p}/standby_sleep_h",                   rn[91])
        self.cache_value(f"{p}/forced_output_delay",               rn[92] / 10.0)
        self.cache_value(f"{p}/forced_output_interval_min",        rn[93])
        self.cache_value(f"{p}/forced_output_count",               rn[94])
        self.cache_value(f"{p}/compensation_site_1",               rn[95])
        self.cache_value(f"{p}/compensation_site_1_resistance_mohm",rn[96])
        self.cache_value(f"{p}/compensation_site_2",               rn[97])
        self.cache_value(f"{p}/compensation_site_2_resistance_mohm",rn[98])
        self.cache_value(f"{p}/cell_diff_alarm_mv",                rn[99])
        self.cache_value(f"{p}/cell_diff_alarm_recovery_mv",       rn[100])
        self.cache_value(f"{p}/charge_request_voltage",            rn[101] / 100.0)
        self.cache_value(f"{p}/charge_request_current",            rn[102])
        self.cache_value(f"{p}/discharge_request_current",         rn[103])
        self.cache_value(f"{p}/pcs_protocol",                      rn[104])
        self.cache_value(f"{p}/current_detector_correction",       signed(rn[105]) / 10.0)

    # --------------------------------------------------------------------------- #
    # Decode SFA (0x1400): Feature enable/disable flags - 80 bits / 10 bytes
    # --------------------------------------------------------------------------- #
    def decode_SFA(self, b, d):
        p = f"{mqtt_prefix}/battery_{b}/features"

        # Byte 0: Voltage alarm/protection enables
        self.cache_value(f"{p}/cell_high_voltage_alarm_en",       (d[0] >> 0) & 1)
        self.cache_value(f"{p}/cell_over_voltage_protect_en",     (d[0] >> 1) & 1)
        self.cache_value(f"{p}/cell_low_voltage_alarm_en",        (d[0] >> 2) & 1)
        self.cache_value(f"{p}/cell_under_voltage_protect_en",    (d[0] >> 3) & 1)
        self.cache_value(f"{p}/pack_high_voltage_alarm_en",       (d[0] >> 4) & 1)
        self.cache_value(f"{p}/pack_over_voltage_protect_en",     (d[0] >> 5) & 1)
        self.cache_value(f"{p}/pack_low_voltage_alarm_en",        (d[0] >> 6) & 1)
        self.cache_value(f"{p}/pack_under_voltage_protect_en",    (d[0] >> 7) & 1)

        # Byte 1: Temperature alarm/protection enables
        self.cache_value(f"{p}/charge_high_temp_alarm_en",        (d[1] >> 0) & 1)
        self.cache_value(f"{p}/charge_over_temp_protect_en",      (d[1] >> 1) & 1)
        self.cache_value(f"{p}/charge_low_temp_alarm_en",         (d[1] >> 2) & 1)
        self.cache_value(f"{p}/charge_under_temp_protect_en",     (d[1] >> 3) & 1)
        self.cache_value(f"{p}/discharge_high_temp_alarm_en",     (d[1] >> 4) & 1)
        self.cache_value(f"{p}/discharge_over_temp_protect_en",   (d[1] >> 5) & 1)
        self.cache_value(f"{p}/discharge_low_temp_alarm_en",      (d[1] >> 6) & 1)
        self.cache_value(f"{p}/discharge_under_temp_protect_en",  (d[1] >> 7) & 1)

        # Byte 2: Ambient/power temp + misc enables
        self.cache_value(f"{p}/ambient_high_temp_alarm_en",       (d[2] >> 0) & 1)
        self.cache_value(f"{p}/ambient_over_temp_protect_en",     (d[2] >> 1) & 1)
        self.cache_value(f"{p}/ambient_low_temp_alarm_en",        (d[2] >> 2) & 1)
        self.cache_value(f"{p}/ambient_under_temp_protect_en",    (d[2] >> 3) & 1)
        self.cache_value(f"{p}/power_high_temp_alarm_en",         (d[2] >> 4) & 1)
        self.cache_value(f"{p}/power_over_temp_protect_en",       (d[2] >> 5) & 1)
        self.cache_value(f"{p}/cell_low_temp_heating_en",         (d[2] >> 6) & 1)

        # Byte 3: Output/display features
        self.cache_value(f"{p}/forced_output_en",                 (d[3] >> 0) & 1)
        self.cache_value(f"{p}/heat_dissipation_en",              (d[3] >> 1) & 1)
        self.cache_value(f"{p}/cap_leds_idle_display_en",         (d[3] >> 2) & 1)

        # Byte 4: Current alarm/protection enables
        self.cache_value(f"{p}/charge_current_alarm_en",          (d[4] >> 0) & 1)
        self.cache_value(f"{p}/charge_over_current_protect_en",   (d[4] >> 1) & 1)
        self.cache_value(f"{p}/charge_over_current2_protect_en",  (d[4] >> 2) & 1)
        self.cache_value(f"{p}/discharge_current_alarm_en",       (d[4] >> 3) & 1)
        self.cache_value(f"{p}/discharge_over_current_protect_en",(d[4] >> 4) & 1)
        self.cache_value(f"{p}/discharge_over_current2_protect_en",(d[4] >> 5) & 1)
        self.cache_value(f"{p}/short_circuit_protect_en",         (d[4] >> 6) & 1)

        # Byte 5: Lock enables
        self.cache_value(f"{p}/short_circuit_lock_en",            (d[5] >> 0) & 1)
        self.cache_value(f"{p}/charge_over_current2_lock_en",     (d[5] >> 2) & 1)
        self.cache_value(f"{p}/discharge_over_current2_lock_en",  (d[5] >> 3) & 1)

        # Byte 6: System features
        self.cache_value(f"{p}/soc_low_alarm_en",                 (d[6] >> 0) & 1)
        self.cache_value(f"{p}/intermittent_charge_en",           (d[6] >> 1) & 1)
        self.cache_value(f"{p}/external_switch_control_en",       (d[6] >> 2) & 1)
        self.cache_value(f"{p}/static_standby_sleep_en",          (d[6] >> 3) & 1)
        self.cache_value(f"{p}/history_recording_en",             (d[6] >> 4) & 1)
        self.cache_value(f"{p}/soc_low_protect_en",               (d[6] >> 5) & 1)
        self.cache_value(f"{p}/active_current_limit_en",          (d[6] >> 6) & 1)
        self.cache_value(f"{p}/passive_current_limit_en",         (d[6] >> 7) & 1)

        # Byte 7: Balancing features
        self.cache_value(f"{p}/balance_module_en",                (d[7] >> 0) & 1)
        self.cache_value(f"{p}/static_balance_indicate_en",       (d[7] >> 1) & 1)
        self.cache_value(f"{p}/static_balance_timeout_en",        (d[7] >> 2) & 1)
        self.cache_value(f"{p}/balance_temp_limit_en",            (d[7] >> 3) & 1)

        # Byte 8: Display/safety features
        self.cache_value(f"{p}/lcd_display_en",                   (d[8] >> 1) & 1)
        self.cache_value(f"{p}/aerosol_detection_en",             (d[8] >> 5) & 1)
        self.cache_value(f"{p}/aerosol_normally_disconnected_en", (d[8] >> 6) & 1)
        self.cache_value(f"{p}/current_detector_temp_comp_en",    (d[8] >> 7) & 1)

        # Byte 9: Hardware failure enables
        self.cache_value(f"{p}/ntc_failure_en",                   (d[9] >> 0) & 1)
        self.cache_value(f"{p}/afe_failure_en",                   (d[9] >> 1) & 1)
        self.cache_value(f"{p}/charge_mosfet_failure_en",         (d[9] >> 2) & 1)
        self.cache_value(f"{p}/discharge_mosfet_failure_en",      (d[9] >> 3) & 1)
        self.cache_value(f"{p}/cell_diff_failure_en",             (d[9] >> 4) & 1)
        self.cache_value(f"{p}/cell_break_en",                    (d[9] >> 5) & 1)
        self.cache_value(f"{p}/key_failure_en",                   (d[9] >> 6) & 1)

    # --------------------------------------------------------------------------- #
    # Calculate the Modbus CRC16
    # --------------------------------------------------------------------------- #
    def calcCRC16(self, data, size):
        crcHi = 0xFF
        crcLo = 0xFF

        crcHiTable = [
            0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
            0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
            0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
            0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
            0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
            0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
            0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
            0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
            0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
            0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
            0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
            0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
            0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
            0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
            0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
            0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
            0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
            0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
            0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
            0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
            0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
            0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
            0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
            0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
            0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
            0x80, 0x41, 0x00, 0xC1, 0x81, 0x40]

        crcLoTable = [
            0x00, 0xC0, 0xC1, 0x01, 0xC3, 0x03, 0x02, 0xC2, 0xC6, 0x06,
            0x07, 0xC7, 0x05, 0xC5, 0xC4, 0x04, 0xCC, 0x0C, 0x0D, 0xCD,
            0x0F, 0xCF, 0xCE, 0x0E, 0x0A, 0xCA, 0xCB, 0x0B, 0xC9, 0x09,
            0x08, 0xC8, 0xD8, 0x18, 0x19, 0xD9, 0x1B, 0xDB, 0xDA, 0x1A,
            0x1E, 0xDE, 0xDF, 0x1F, 0xDD, 0x1D, 0x1C, 0xDC, 0x14, 0xD4,
            0xD5, 0x15, 0xD7, 0x17, 0x16, 0xD6, 0xD2, 0x12, 0x13, 0xD3,
            0x11, 0xD1, 0xD0, 0x10, 0xF0, 0x30, 0x31, 0xF1, 0x33, 0xF3,
            0xF2, 0x32, 0x36, 0xF6, 0xF7, 0x37, 0xF5, 0x35, 0x34, 0xF4,
            0x3C, 0xFC, 0xFD, 0x3D, 0xFF, 0x3F, 0x3E, 0xFE, 0xFA, 0x3A,
            0x3B, 0xFB, 0x39, 0xF9, 0xF8, 0x38, 0x28, 0xE8, 0xE9, 0x29,
            0xEB, 0x2B, 0x2A, 0xEA, 0xEE, 0x2E, 0x2F, 0xEF, 0x2D, 0xED,
            0xEC, 0x2C, 0xE4, 0x24, 0x25, 0xE5, 0x27, 0xE7, 0xE6, 0x26,
            0x22, 0xE2, 0xE3, 0x23, 0xE1, 0x21, 0x20, 0xE0, 0xA0, 0x60,
            0x61, 0xA1, 0x63, 0xA3, 0xA2, 0x62, 0x66, 0xA6, 0xA7, 0x67,
            0xA5, 0x65, 0x64, 0xA4, 0x6C, 0xAC, 0xAD, 0x6D, 0xAF, 0x6F,
            0x6E, 0xAE, 0xAA, 0x6A, 0x6B, 0xAB, 0x69, 0xA9, 0xA8, 0x68,
            0x78, 0xB8, 0xB9, 0x79, 0xBB, 0x7B, 0x7A, 0xBA, 0xBE, 0x7E,
            0x7F, 0xBF, 0x7D, 0xBD, 0xBC, 0x7C, 0xB4, 0x74, 0x75, 0xB5,
            0x77, 0xB7, 0xB6, 0x76, 0x72, 0xB2, 0xB3, 0x73, 0xB1, 0x71,
            0x70, 0xB0, 0x50, 0x90, 0x91, 0x51, 0x93, 0x53, 0x52, 0x92,
            0x96, 0x56, 0x57, 0x97, 0x55, 0x95, 0x94, 0x54, 0x9C, 0x5C,
            0x5D, 0x9D, 0x5F, 0x9F, 0x9E, 0x5E, 0x5A, 0x9A, 0x9B, 0x5B,
            0x99, 0x59, 0x58, 0x98, 0x88, 0x48, 0x49, 0x89, 0x4B, 0x8B,
            0x8A, 0x4A, 0x4E, 0x8E, 0x8F, 0x4F, 0x8D, 0x4D, 0x4C, 0x8C,
            0x44, 0x84, 0x85, 0x45, 0x87, 0x47, 0x46, 0x86, 0x82, 0x42,
            0x43, 0x83, 0x41, 0x81, 0x80, 0x40]

        index = 0
        while index < size:
            crc = crcHi ^ data[index]
            crcHi = crcLo ^ crcHiTable[crc]
            crcLo = crcLoTable[crc]
            index += 1

        return (crcHi * 0x0100) + crcLo


# --------------------------------------------------------------------------- #
# Print the usage help
# --------------------------------------------------------------------------- #
def printHelp():
    print("\nUsage:")
    print("  python seplos3mqtt.py")
    print("")
    print("Seplos3mqtt gets the configuration from seplos3mqtt.ini")
    print("Remember to create the file and include the following data:")
    print("[seplos3mqtt]")
    print("serial = ")
    print("mqtt_server = ")
    print("mqtt_port = ")
    print("mqtt_user = ")
    print("mqtt_pass = ")
    print("mqtt_prefix = ")
    print("")


# --------------------------------------------------------------------------- #
# get variable config from environment or config file
# --------------------------------------------------------------------------- #
def get_config_variable(name, default='mandatory'):
    try:
        value = os.getenv(name)
        if value is not None:
            return value

        config = configparser.ConfigParser()
        config.read('seplos3mqtt.ini')
        if not config.sections():
            raise FileNotFoundError()

        return config['seplos3mqtt'][name]

    except configparser.NoSectionError as e:
        if default != 'mandatory':
            return default
        else:
            print(f'Error: Section [seplos3mqtt] not found in the file seplos3mqtt.ini for variable {name}, exception: {e}')
            printHelp()
            sys.exit()
    except configparser.NoOptionError as e:
        if default != 'mandatory':
            return default
        else:
            print(f'Error: Parameter {name} not found in environment variable or in the file seplos3mqtt.ini Details: {e}')
            printHelp()
            sys.exit()
    except FileNotFoundError as e:
        if default != 'mandatory':
            return default
        else:
            print(f'Error: seplos3mqtt.ini was not found or environment variable {name} not defined.')
            printHelp()
            sys.exit()
    except Exception as e:
        print(f'Unexpected error: {e}')
        printHelp()
        sys.exit()


# --------------------------------------------------------------------------- #
# main routine
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    print(" ")

    try:
        port        = get_config_variable('serial')
        mqtt_server = get_config_variable('mqtt_server')
        mqtt_port   = int(get_config_variable('mqtt_port', "1883"))
        mqtt_user   = get_config_variable('mqtt_user', "")
        mqtt_pass   = get_config_variable('mqtt_pass', "")
        mqtt_prefix = get_config_variable('mqtt_prefix', "seplos")

        with SerialSnooper(port, mqtt_server, mqtt_port, mqtt_user, mqtt_pass) as sniffer:
            while True:
                data = sniffer.read_raw()
                sniffer.process_data(data)
                sniffer.flush_cache()

    except Exception as e:
        print(f'Unexpected error: {e}')
        printHelp()

# Register map reference (Seplos BMS v3):
# PIA  0x1000  18 reg  Pack main info (voltage, current, SOC, temps, etc.)
# PIB  0x1100  26 reg  Cell voltages (16) + cell temps (8) + ambient + power temp
# PIC  0x1200  144 bit Per-cell alarms, mode flags, protection flags, FET states
# SPA  0x1300  106 reg Settings and thresholds
# SFA  0x1400  80 bit  Feature enable/disable switches
# SCA  0x150D  13 reg  Calibration + FET control (write-only, not decoded)
# 0x1700       51 reg  Manufacturer/serial number string (static, not decoded)
