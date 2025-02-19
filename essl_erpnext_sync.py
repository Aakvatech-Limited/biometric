import local_config as config
import requests
import datetime
import json
import os
import sys
import time
import logging
from logging.handlers import RotatingFileHandler
import shelve  # Using shelve for status persistence

EMPLOYEE_NOT_FOUND_ERROR_MESSAGE = "No Employee found for the given employee field value"
EMPLOYEE_INACTIVE_ERROR_MESSAGE = "Transactions cannot be created for an Inactive Employee"
DUPLICATE_EMPLOYEE_CHECKIN_ERROR_MESSAGE = "This employee already has a log with the same timestamp"
allowlisted_errors = [EMPLOYEE_NOT_FOUND_ERROR_MESSAGE, EMPLOYEE_INACTIVE_ERROR_MESSAGE, DUPLICATE_EMPLOYEE_CHECKIN_ERROR_MESSAGE]

if hasattr(config, 'allowed_exceptions'):
    allowlisted_errors_temp = []
    for error_number in config.allowed_exceptions:
        allowlisted_errors_temp.append(allowlisted_errors[error_number - 1])
    allowlisted_errors = allowlisted_errors_temp

device_punch_values_IN = getattr(config, 'device_punch_values_IN', [0, 4])
device_punch_values_OUT = getattr(config, 'device_punch_values_OUT', [1, 5])
ERPNEXT_VERSION = getattr(config, 'ERPNEXT_VERSION', 14)

# Notes:
# Status Keys in status file (shelve)
#  - lift_off_timestamp
#  - mission_accomplished_timestamp
#  - <device_id>_pull_timestamp
#  - <device_id>_push_timestamp
#  - <shift_type>_sync_timestamp

def main():
    """Takes care of checking if it is time to pull data based on config,
    then calling the relevant functions to pull data and push to ERPNext."""
    
    status_file = os.path.join(config.LOGS_DIRECTORY, 'status')  # Removed .json extension for shelve
    with shelve.open(status_file) as status:
        try:
            last_lift_off_timestamp = _safe_convert_date(status.get('lift_off_timestamp'), "%Y-%m-%d %H:%M:%S.%f")
            if (last_lift_off_timestamp and last_lift_off_timestamp < datetime.datetime.now() - datetime.timedelta(minutes=config.PULL_FREQUENCY)) or not last_lift_off_timestamp:
                status['lift_off_timestamp'] = str(datetime.datetime.now())
                info_logger.info("Cleared for lift off!")
                
                for device in config.devices:
                    device_attendance_logs = None
                    info_logger.info("Processing Device: " + device['device_id'])
                    dump_file = get_dump_file_name_and_directory(device['device_id'], device['ip'])
                    
                    if os.path.exists(dump_file):
                        info_logger.error('Device Attendance Dump Found in Log Directory. Retrying with dumped data.')
                        with open(dump_file, 'r') as f:
                            file_contents = f.read()
                            if file_contents:
                                device_attendance_logs = list(map(lambda x: _apply_function_to_key(x, 'timestamp', datetime.datetime.fromtimestamp), json.loads(file_contents)))

                    try:
                        pull_process_and_push_data(device, status, device_attendance_logs)
                        status[f'{device["device_id"]}_push_timestamp'] = str(datetime.datetime.now())
                        if os.path.exists(dump_file):
                            os.remove(dump_file)
                        info_logger.info("Successfully processed Device: " + device['device_id'])
                    except Exception as e:
                        error_logger.exception('Exception when calling pull_process_and_push_data function for device' + json.dumps(device, default=str))
                
                if hasattr(config, 'shift_type_device_mapping'):
                    update_shift_last_sync_timestamp(config.shift_type_device_mapping, status)
                
                status['mission_accomplished_timestamp'] = str(datetime.datetime.now())
                info_logger.info("Mission Accomplished!")
        except Exception as e:
            error_logger.exception('Exception has occurred in the main function...')

def pull_process_and_push_data(device, status, device_attendance_logs=None):
    """ Takes a single device config and status object as params and pulls data from that device. """
    attendance_success_log_file = '_'.join(["attendance_success_log", device['device_id']])
    attendance_failed_log_file = '_'.join(["attendance_failed_log", device['device_id']])
    attendance_success_logger = setup_logger(attendance_success_log_file, os.path.join(config.LOGS_DIRECTORY, attendance_success_log_file) + '.log')
    attendance_failed_logger = setup_logger(attendance_failed_log_file, os.path.join(config.LOGS_DIRECTORY, attendance_failed_log_file) + '.log')
    
    if not device_attendance_logs:
        device_attendance_logs = get_all_attendance_from_device(device['ip'], status, device_id=device['device_id'], 
                                                             clear_from_device_on_fetch=device['clear_from_device_on_fetch'])
        if not device_attendance_logs:
            return
        

    # Collect records for bulk processing
    records_to_insert = []
    for device_attendance_log in device_attendance_logs:
        punch_direction = device['punch_direction']
        if punch_direction == 'AUTO':
            if device_attendance_log['punch'] in device_punch_values_OUT:
                punch_direction = 'OUT'
            elif device_attendance_log['punch'] in device_punch_values_IN:
                punch_direction = 'IN'
            else:
                punch_direction = None

        records_to_insert.append({
            "attendance_device_id": device_attendance_log['user_id'],
            "timestamp": device_attendance_log['timestamp'].isoformat(),  # Convert datetime to ISO format
            "punch_type": punch_direction,
            "device_id": device['device_id'],
            "status": "Pending"  # Default status
        })

    # Send records in bulk to ERPNext API
    erpnext_status_code, erpnext_message = send_to_erpnext_bulk(records_to_insert)
    if erpnext_status_code == 200:
        attendance_success_logger.info(f"Bulk insert successful: {erpnext_message}")
    else:
        attendance_failed_logger.error(f"Bulk insert failed: {erpnext_message}")
        if not any(error in erpnext_message for error in allowlisted_errors):
            raise Exception('Bulk insert to ERPNext failed.')

def get_all_attendance_from_device(ip, status, port=4370, timeout=30, device_id=None, clear_from_device_on_fetch=False):
    """Fetch attendance data from ESSL device."""
    try:
        # Replace this with ESSL-specific API calls
        # Example: Use requests to call ESSL device API
        response = requests.get(f"http://{ip}/api/attendance", timeout=timeout)
        response.raise_for_status()
        attendances = response.json()

        if device_id:
            status[f'{device_id}_push_timestamp'] = None
            status[f'{device_id}_pull_timestamp'] = str(datetime.datetime.now())
            
        if len(attendances):
            dump_file_name = get_dump_file_name_and_directory(device_id, ip)
            with open(dump_file_name, 'w+') as f:
                f.write(json.dumps(attendances, default=datetime.datetime.timestamp))
            if clear_from_device_on_fetch:
                # Clear attendance data from device if required
                requests.post(f"http://{ip}/api/clear_attendance")
        
        return attendances
    except Exception as e:
        error_logger.exception(f"Exception when fetching from ESSL device {ip}: {str(e)}")
        raise Exception('Device fetch failed.')
    

def send_to_erpnext_bulk(records):
    """
    Send bulk biometric data to the ERPNext API endpoint.
    """
    url = f"{config.ERPNEXT_URL}/api/method/biometric_client.biometric_client.api.upload_bulk_biometric_data"
    headers = {
        'Authorization': f"token {config.ERPNEXT_API_KEY}:{config.ERPNEXT_API_SECRET}",
        'Accept': 'application/json'
    }

    try:
        response = requests.post(url, headers=headers, json=records)
        if response.status_code == 200:
            return 200, response.json().get("message", "Bulk data processed successfully")
        else:
            error_str = _safe_get_error_str(response)
            return response.status_code, error_str
    except Exception as e:
        error_logger.exception(f"API call to ERPNext failed: {str(e)}")
        return 500, str(e)

def update_shift_last_sync_timestamp(shift_type_device_mapping, status):
    """Updated to accept status parameter"""
    for shift_type_device_map in shift_type_device_mapping:
        all_devices_pushed = True
        pull_timestamp_array = []
        for device_id in shift_type_device_map['related_device_id']:
            if not status.get(f'{device_id}_push_timestamp'):
                all_devices_pushed = False
                break
            pull_timestamp_array.append(_safe_convert_date(status.get(f'{device_id}_pull_timestamp'), "%Y-%m-%d %H:%M:%S.%f"))
        
        if all_devices_pushed and pull_timestamp_array:  # Added check for non-empty array
            min_pull_timestamp = min(pull_timestamp_array)
            if isinstance(shift_type_device_map['shift_type_name'], str):
                shift_type_device_map['shift_type_name'] = [shift_type_device_map['shift_type_name']]
            
            for shift in shift_type_device_map['shift_type_name']:
                try:
                    sync_current_timestamp = _safe_convert_date(status.get(f'{shift}_sync_timestamp'), "%Y-%m-%d %H:%M:%S.%f")
                    if (sync_current_timestamp and min_pull_timestamp > sync_current_timestamp) or (min_pull_timestamp and not sync_current_timestamp):
                        response_code = send_shift_sync_to_erpnext(shift, min_pull_timestamp)
                        if response_code == 200:
                            status[f'{shift}_sync_timestamp'] = str(min_pull_timestamp)
                except Exception as e:
                    error_logger.exception('Exception in update_shift_last_sync_timestamp, for shift:'+shift)

def send_shift_sync_to_erpnext(shift_type_name, sync_timestamp):
    url = config.ERPNEXT_URL + "/api/resource/Shift Type/" + shift_type_name
    headers = {
        'Authorization': "token "+ config.ERPNEXT_API_KEY + ":" + config.ERPNEXT_API_SECRET,
        'Accept': 'application/json'
    }
    data = {
        "last_sync_of_checkin" : str(sync_timestamp)
    }
    try:
        response = requests.request("PUT", url, headers=headers, data=json.dumps(data))
        if response.status_code == 200:
            info_logger.info("\t".join(['Shift Type last_sync_of_checkin Updated', str(shift_type_name), str(sync_timestamp.timestamp())]))
        else:
            error_str = _safe_get_error_str(response)
            error_logger.error('\t'.join(['Error during ERPNext Shift Type API Call.', str(shift_type_name), str(sync_timestamp.timestamp()), error_str]))
        return response.status_code
    except:
        error_logger.exception("\t".join(['exception when updating last_sync_of_checkin in Shift Type', str(shift_type_name), str(sync_timestamp.timestamp())]))

def get_last_line_from_file(file):
    line = None
    if os.stat(file).st_size < 5000:
        with open(file, 'r') as f:
            for line in f:
                pass
    else:
        with open(file, 'rb') as f:
            f.seek(-2, os.SEEK_END)
            while f.read(1) != b'\n':
                f.seek(-2, os.SEEK_CUR)
            line = f.readline().decode()
    return line

def setup_logger(name, log_file, level=logging.INFO, formatter=None):
    if not formatter:
        formatter = logging.Formatter('%(asctime)s\t%(levelname)s\t%(message)s')

    handler = RotatingFileHandler(log_file, maxBytes=10000000, backupCount=50)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.hasHandlers():
        logger.addHandler(handler)

    return logger

def get_dump_file_name_and_directory(device_id, device_ip):
    return config.LOGS_DIRECTORY + '/' + device_id + "_" + device_ip.replace('.', '_') + '_last_fetch_dump.json'

def _apply_function_to_key(obj, key, fn):
    obj[key] = fn(obj[key])
    return obj

def _safe_convert_date(datestring, pattern):
    try:
        return datetime.datetime.strptime(datestring, pattern)
    except:
        return None

def _safe_get_error_str(res):
    try:
        error_json = json.loads(res._content)
        if 'exc' in error_json:
            error_str = json.loads(error_json['exc'])[0]
        else:
            error_str = json.dumps(error_json)
    except:
        error_str = str(res.__dict__)
    return error_str

# Setup logger and status
if not os.path.exists(config.LOGS_DIRECTORY):
    os.makedirs(config.LOGS_DIRECTORY)
error_logger = setup_logger('error_logger', '/'.join([config.LOGS_DIRECTORY, 'error.log']), logging.ERROR)
info_logger = setup_logger('info_logger', '/'.join([config.LOGS_DIRECTORY, 'logs.log']))

def infinite_loop(sleep_time=15):
    print("Service Running...")
    while True:
        try:
            main()
            time.sleep(sleep_time)
        except BaseException as e:
            print(e)

if __name__ == "__main__":
    infinite_loop()