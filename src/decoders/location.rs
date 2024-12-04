// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::util::decode_standard;

use super::bool::{lowercase_bool, lowercase_int_bool};
use log::{error, warn};
use nom::{
    bytes::complete::take,
    number::complete::{le_f64, le_i32, le_i64, le_u32, le_u8},
};
use std::mem::size_of;

#[derive(Debug, Clone, Default)]
struct LocationTrackerState {
    distance_filter: f64,
    desired_accuracy: f64,
    updating_location: u8,
    requesting_location: u8,
    requesting_ranging: u8,
    updating_ranging: u8,
    updating_heading: u8,
    heading_filter: f64,
    allows_location_prompts: u8,
    allows_altered_locations: u8,
    dynamic_accuracy: u8,
    previous_authorization_status_valid: u8,
    previous_authorization_status: i32,
    limits_precision: u8,
    activity_type: i64,
    pauses_location_updates: i32,
    paused: u8,
    allows_background_updates: u8,
    shows_background_location: u8,
    allows_map_correction: u8,
    batching_location: u8,
    updating_vehicle_speed: u8,
    updating_vehicle_heading: u8,
    match_info: u8,
    ground_altitude: u8,
    fusion_info: u8,
    courtesy_prompt: u8,
    is_authorized_for_widgets: u8,
}

/// Convert Core Location Client Autherization Status code to string
pub(crate) fn client_authorization_status(status: &str) -> String {
    let message = match status {
        "0" => "Not Determined",
        "1" => "Restricted",
        "2" => "Denied",
        "3" => "Authorized Always",
        "4" => "Authorized When In Use",
        _ => {
            warn!(
                "Unknown Core Location client authorization status: {}",
                status
            );
            status
        }
    };
    message.to_string()
}

/// Convert Core Location Daemon Status type to string
pub(crate) fn daemon_status_type(status: &str) -> String {
    // Found in dyldcache liblog
    let message = match status {
        "0" => "Reachability Unavailable",
        "1" => "Reachability Small",
        "2" => "Reachability Large",
        "56" => "Reachability Unachievable",
        _ => {
            warn!("Unknown Core Location daemon status type: {}", status);
            status
        }
    };
    message.to_string()
}

/// Convert Core Location Subhaverester id to string
pub(crate) fn subharvester_identifier(status: &str) -> String {
    // Found in dyldcache liblog
    let message = match status {
        "1" => "Wifi",
        "2" => "Tracks",
        "3" => "Realtime",
        "4" => "App",
        "5" => "Pass",
        "6" => "Indoor",
        "7" => "Pressure",
        "8" => "Poi",
        "9" => "Trace",
        "10" => "Avenger",
        "11" => "Altimeter",
        "12" => "Ionosphere",
        "13" => "Unknown",
        _ => {
            warn!(
                "Unknown Core Location subhaverster identifier type: {}",
                status
            );
            status
        }
    };
    message.to_string()
}

/// Convert Core Location SQLITE code to string
pub(crate) fn sqlite(status: &str) -> String {
    let decoded_data_result = decode_standard(status);
    let decoded_data = match decoded_data_result {
        Ok(result) => result,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to base64 decodesqlite {}, error: {:?}",
                status, err
            );
            return String::from("Failed to base64 decode sqlite details");
        }
    };

    let message_result = get_sqlite_data(&decoded_data);
    match message_result {
        Ok((_, result)) => result,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to get sqlite {}, error code, error: {:?}",
                status, err
            );
            String::from("Failed to get sqlite error")
        }
    }
}

/// Get the SQLITE error message
fn get_sqlite_data(data: &[u8]) -> nom::IResult<&[u8], String> {
    let (empty, sqlite_data) = take(size_of::<u32>())(data)?;
    let (_, sqlite_code) = le_u32(sqlite_data)?;

    // Found at https://www.sqlite.org/rescode.html
    let message = match sqlite_code {
        0 => "SQLITE OK",
        1 => "SQLITE ERROR",
        2 => "SQLITE INTERNAL",
        3 => "SQLITE PERM",
        4 => "SQLITE ABORT",
        5 => "SQLITE BUSY",
        6 => "SQLITE LOCKED",
        7 => "SQLITE NOMEM",
        8 => "SQLITE READ ONLY",
        9 => "SQLITE INTERRUPT",
        10 => "SQLITE IO ERR",
        11 => "SQLITE CORRUPT",
        12 => "SQLITE NOT FOUND",
        13 => "SQLITE FULL",
        14 => "SQLITE CAN'T OPEN",
        15 => "SQLITE PROTOCOL",
        16 => "SQLITE EMPTY",
        17 => "SQLITE SCHEMA",
        18 => "SQLITE TOO BIG",
        19 => "SQLITE CONSTRAINT",
        20 => "SQLITE MISMATCH",
        21 => "SQLITE MISUSE",
        22 => "SQLITE NO LFS",
        23 => "SQLITE AUTH",
        24 => "SQLITE FORMAT",
        25 => "SQLITE RANGE",
        26 => "SQLITE NOT A DB",
        27 => "SQLITE NOTICE",
        28 => "SQLITE WARNING",
        100 => "SQLITE ROW",
        101 => "SQLITE DONE",
        266 => "SQLITE IO ERR READ",
        _ => {
            warn!(
                "[macos-unifiedlogs] Unknown Core Location sqlite error: {}",
                sqlite_code
            );
            "Unknown Core Location sqlite error"
        }
    };

    Ok((empty, message.to_string()))
}

/// Parse the manager tracker state data
pub(crate) fn client_manager_state_tracker_state(status: &str) -> String {
    let decoded_data_result = decode_standard(status);
    let decoded_data = match decoded_data_result {
        Ok(result) => result,
        Err(err) => {
            error!("[macos-unifiedlogs] Failed to base64 decode client manager tracker state {}, error: {:?}", status, err);
            return String::from("Failed to base64 decode client manager tracker state");
        }
    };

    let message_result = get_state_tracker_data(&decoded_data);
    match message_result {
        Ok((_, result)) => result,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to get client tracker data {}, error: {:?}",
                status, err
            );
            String::from("Failed to get client tracker data")
        }
    }
}

/// Get the tracker data
pub(crate) fn get_state_tracker_data(data: &[u8]) -> nom::IResult<&[u8], String> {
    let (location_data, location_enabled_data) = take(size_of::<u32>())(data)?;
    let (location_data, location_restricted_data) = take(size_of::<u32>())(location_data)?;

    let (_, location_enabled) = le_u32(location_enabled_data)?;
    let (_, location_restricted) = le_u32(location_restricted_data)?;

    Ok((
        location_data,
        format!(
            "{{\"locationRestricted\":{}, \"locationServicesenabledStatus\":{}}}",
            lowercase_bool(&format!("{}", location_restricted)),
            location_enabled
        ),
    ))
}

/// Parse location tracker state data
pub(crate) fn location_manager_state_tracker_state(status: &str) -> String {
    let decoded_data_result = decode_standard(status);
    let decoded_data = match decoded_data_result {
        Ok(result) => result,
        Err(err) => {
            error!("[macos-unifiedlogs] Failed to base64 decode location manager tracker state {}, error: {:?}", status, err);
            return String::from("Failed to base64 decode logon manager trackder data");
        }
    };

    let message_result = get_location_tracker_state(&decoded_data);
    match message_result {
        Ok((_, result)) => result,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to get location tracker data {}, error: {:?}",
                status, err
            );
            String::from("Failed to get logon manager trackder data")
        }
    }
}

/// Get the location state data
pub(crate) fn get_location_tracker_state(data: &[u8]) -> nom::IResult<&[u8], String> {
    // Found at https://github.com/cmsj/ApplePrivateHeaders/blob/main/macOS/11.3/System/Library/Frameworks/CoreLocation.framework/Versions/A/CoreLocation/CoreLocation-Structs.h and in dyldcache
    let (location_data, distance_filter_data) = take(size_of::<u64>())(data)?;
    let (location_data, desired_accuracy_data) = take(size_of::<u64>())(location_data)?;
    let (location_data, updating_location_data) = take(size_of::<u8>())(location_data)?;
    let (location_data, requesting_location_data) = take(size_of::<u8>())(location_data)?;
    let (location_data, requesting_ranging_data) = take(size_of::<u8>())(location_data)?;
    let (location_data, updating_ranging_data) = take(size_of::<u8>())(location_data)?;
    let (location_data, updating_heading_data) = take(size_of::<u8>())(location_data)?;

    // Padding? Reserved?
    let unknown_data_length: usize = 3;
    let (location_data, _) = take(unknown_data_length)(location_data)?;
    let (location_data, heading_filter_data) = take(size_of::<u64>())(location_data)?;
    let (location_data, allows_location_prompts_data) = take(size_of::<u8>())(location_data)?;
    let (location_data, allows_altered_accessory_location_data) =
        take(size_of::<u8>())(location_data)?;
    let (location_data, dynamic_accuracy_reduction_enabled_data) =
        take(size_of::<u8>())(location_data)?;

    let (location_data, previous_authorization_status_valid_data) =
        take(size_of::<u8>())(location_data)?;
    let (location_data, previous_authorization_status_data) =
        take(size_of::<u32>())(location_data)?;
    let (location_data, limits_precision_data) = take(size_of::<u8>())(location_data)?;

    // padding? Reserved?
    let unkonwn_data_length2: usize = 7;
    let (location_data, _) = take(unkonwn_data_length2)(location_data)?;

    let (location_data, activity_type_data) = take(size_of::<u64>())(location_data)?;
    let (location_data, pause_location_updates_auto_data) = take(size_of::<u32>())(location_data)?;

    let (location_data, paused_data) = take(size_of::<u8>())(location_data)?;
    let (location_data, allows_background_location_data) = take(size_of::<u8>())(location_data)?;
    let (location_data, shows_background_location_data) = take(size_of::<u8>())(location_data)?;
    let (location_data, allows_map_correction_data) = take(size_of::<u8>())(location_data)?;

    let (_, distance_filter) = le_f64(distance_filter_data)?;
    let (_, desired_accuracy) = le_f64(desired_accuracy_data)?;
    let (_, updating_location) = le_u8(updating_location_data)?;
    let (_, requesting_location) = le_u8(requesting_location_data)?;
    let (_, requesting_ranging) = le_u8(requesting_ranging_data)?;
    let (_, updating_ranging) = le_u8(updating_ranging_data)?;
    let (_, updating_heading) = le_u8(updating_heading_data)?;

    let (_, heading_filter) = le_f64(heading_filter_data)?;
    let (_, allows_location_prompts) = le_u8(allows_location_prompts_data)?;
    let (_, allows_altered_locations) = le_u8(allows_altered_accessory_location_data)?;
    let (_, dynamic_accuracy) = le_u8(dynamic_accuracy_reduction_enabled_data)?;

    let (_, previous_authorization_status_valid) = le_u8(previous_authorization_status_valid_data)?;
    let (_, previous_authorization_status) = le_i32(previous_authorization_status_data)?;
    let (_, limits_precision) = le_u8(limits_precision_data)?;
    let (_, activity_type) = le_i64(activity_type_data)?;
    let (_, pauses_location_updates) = le_i32(pause_location_updates_auto_data)?;

    let (_, paused) = le_u8(paused_data)?;
    let (_, allows_background_updates) = le_u8(allows_background_location_data)?;
    let (_, shows_background_location) = le_u8(shows_background_location_data)?;
    let (_, allows_map_correction) = le_u8(allows_map_correction_data)?;

    let mut tracker = LocationTrackerState {
        distance_filter,
        desired_accuracy,
        updating_location,
        requesting_location,
        requesting_ranging,
        updating_ranging,
        updating_heading,
        heading_filter,
        allows_location_prompts,
        allows_altered_locations,
        dynamic_accuracy,
        previous_authorization_status_valid,
        previous_authorization_status,
        limits_precision,
        activity_type,
        pauses_location_updates,
        paused,
        allows_background_updates,
        shows_background_location,
        allows_map_correction,
        batching_location: 0,
        updating_vehicle_speed: 0,
        updating_vehicle_heading: 0,
        match_info: 0,
        ground_altitude: 0,
        fusion_info: 0,
        courtesy_prompt: 0,
        is_authorized_for_widgets: 0,
    };

    // Sometimes location data only has 64 bytes of data. Seen only on Catalina. Though this might be a setting configuration?
    // All other systems have 72 bytes of location data even systems before Catalina (ex: Mojave)
    // Return early if we only have 64 bytes to work with
    let catalina_size = 64;
    if data.len() == catalina_size {
        return Ok((location_data, location_tracker_object(&tracker)));
    }

    let (location_data, batching_location_data) = take(size_of::<u8>())(location_data)?;
    let (location_data, updating_vehicle_speed_data) = take(size_of::<u8>())(location_data)?;

    let (location_data, updating_vehicle_heading_data) = take(size_of::<u8>())(location_data)?;
    let (location_data, match_info_data) = take(size_of::<u8>())(location_data)?;
    let (location_data, ground_altitude_data) = take(size_of::<u8>())(location_data)?;
    let (location_data, fusion_info_data) = take(size_of::<u8>())(location_data)?;
    let (location_data, courtesy_prompt_data) = take(size_of::<u8>())(location_data)?;

    let (location_data, is_authorized_widget_data) = take(size_of::<u8>())(location_data)?;

    let (_, batching_location) = le_u8(batching_location_data)?;
    let (_, updating_vehicle) = le_u8(updating_vehicle_speed_data)?;

    let (_, updating_vehicle_heading) = le_u8(updating_vehicle_heading_data)?;
    let (_, match_info) = le_u8(match_info_data)?;
    let (_, ground_altitude) = le_u8(ground_altitude_data)?;
    let (_, fusion_info) = le_u8(fusion_info_data)?;
    let (_, courtesy_prompt) = le_u8(courtesy_prompt_data)?;
    let (_, is_authorized) = le_u8(is_authorized_widget_data)?;

    tracker.batching_location = batching_location;
    tracker.updating_vehicle_speed = updating_vehicle;
    tracker.updating_vehicle_heading = updating_vehicle_heading;
    tracker.match_info = match_info;
    tracker.ground_altitude = ground_altitude;
    tracker.fusion_info = fusion_info;
    tracker.courtesy_prompt = courtesy_prompt;
    tracker.is_authorized_for_widgets = is_authorized;

    Ok((location_data, location_tracker_object(&tracker)))
}

/// Create the location tracker json object
fn location_tracker_object(tracker: &LocationTrackerState) -> String {
    format!(
        "{{
            \"distanceFilter\":{}, 
            \"desiredAccuracy\":{}, 
            \"updatingLocation\":{}, 
            \"requestingLocation\":{}, 
            \"requestingRanging\":{}, 
            \"updatingRanging\":{},
            \"updatingHeading\":{},
            \"headingFilter\":{},
            \"allowsLocationPrompts\":{},
            \"allowsAlteredAccessoryLocations\":{},
            \"dynamicAccuracyReductionEnabled\":{},
            \"previousAuthorizationStatusValid\":{},
            \"previousAuthorizationStatus\":{},
            \"limitsPrecision\":{},
            \"activityType\":{},
            \"pausesLocationUpdatesAutomatically\":{},
            \"paused\":{},
            \"allowsBackgroundLocationUpdates\":{},
            \"showsBackgroundLocationIndicator\":{},
            \"allowsMapCorrection\":{},
            \"batchingLocation\":{},
            \"updatingVehicleSpeed\":{},
            \"updatingVehicleHeading\":{},
            \"matchInfoEnabled\":{},
            \"groundAltitudeEnabled\":{},
            \"fusionInfoEnabled\":{},
            \"courtesyPromptNeeded\":{},
            \"isAuthorizedForWidgetUpdates\":{},
        }}",
        tracker.distance_filter,
        tracker.desired_accuracy,
        lowercase_int_bool(&tracker.updating_location),
        lowercase_int_bool(&tracker.requesting_location),
        lowercase_int_bool(&tracker.requesting_ranging),
        lowercase_int_bool(&tracker.updating_ranging),
        lowercase_int_bool(&tracker.updating_heading),
        tracker.heading_filter,
        lowercase_int_bool(&tracker.allows_location_prompts),
        lowercase_int_bool(&tracker.allows_altered_locations),
        lowercase_int_bool(&tracker.dynamic_accuracy),
        lowercase_int_bool(&tracker.previous_authorization_status_valid),
        tracker.previous_authorization_status,
        lowercase_int_bool(&tracker.limits_precision),
        tracker.activity_type,
        tracker.pauses_location_updates,
        lowercase_int_bool(&tracker.paused),
        lowercase_int_bool(&tracker.allows_background_updates),
        lowercase_int_bool(&tracker.shows_background_location),
        lowercase_int_bool(&tracker.allows_map_correction),
        lowercase_int_bool(&tracker.batching_location),
        lowercase_int_bool(&tracker.updating_vehicle_speed),
        lowercase_int_bool(&tracker.updating_vehicle_heading),
        lowercase_int_bool(&tracker.match_info),
        lowercase_int_bool(&tracker.ground_altitude),
        lowercase_int_bool(&tracker.fusion_info),
        lowercase_int_bool(&tracker.courtesy_prompt),
        lowercase_int_bool(&tracker.is_authorized_for_widgets),
    )
}

/// Parse location tracker state data
pub(crate) fn io_message(data: &str) -> String {
    // Found in dyldcache
    let message = match data {
        "3758097008" => "CanSystemSleep",
        "3758097024" => "SystemWillSleep",
        "3758097040" => "SystemWillNotSleep",
        "3758097184" => "SystemWillPowerOn",
        "3758097168" => "SystemWillRestart",
        "3758097152" => "SystemHasPoweredOn",
        "3758097200" => "CopyClientID",
        "3758097216" => "SystemCapabilityChange",
        "3758097232" => "DeviceSignaledWakeup",
        "3758096400" => "ServiceIsTerminated",
        "3758096416" => "ServiceIsSuspended",
        "3758096432" => "ServiceIsResumed",
        "3758096640" => "ServiceIsRequestingClose",
        "3758096641" => "ServiceIsAttemptingOpen",
        "3758096656" => "ServiceWasClosed",
        "3758096672" => "ServiceBusyStateChange",
        "3758096680" => "ConsoleSecurityChange",
        "3758096688" => "ServicePropertyChange",
        "3758096896" => "CanDevicePowerOff",
        "3758096912" => "DeviceWillPowerOff",
        "3758096928" => "DeviceWillNotPowerOff",
        "3758096944" => "DeviceHasPoweredOn",
        "3758096976" => "SystemWillPowerOff",
        "3758096981" => "SystemPagingOff",
        _ => {
            warn!("[macos-unifiedlogs] Unknown IO Message: {}", data);
            data
        }
    };
    message.to_string()
}

/// Parse and get the location Daemon tracker
pub(crate) fn get_daemon_status_tracker(data: &[u8]) -> nom::IResult<&[u8], String> {
    // https://gist.github.com/razvand/578f94748b624f4d47c1533f5a02b095
    let (location_data, level_data) = take(size_of::<u64>())(data)?;
    let (location_data, charged_data) = take(size_of::<u8>())(location_data)?;
    let (location_data, connected_data) = take(size_of::<u8>())(location_data)?;
    let (location_data, charger_type_data) = take(size_of::<u32>())(location_data)?;
    let (location_data, was_connected_data) = take(size_of::<u8>())(location_data)?;

    let reserved_size: usize = 9;
    let (location_data, _reserved) = take(reserved_size)(location_data)?;

    let (location_data, reachability_data) = take(size_of::<u32>())(location_data)?;
    let (location_data, thermal_level_data) = take(size_of::<u32>())(location_data)?;
    let (location_data, airplane_data) = take(size_of::<u8>())(location_data)?;
    let (location_data, battery_saver_data) = take(size_of::<u8>())(location_data)?;
    let (location_data, push_service_data) = take(size_of::<u8>())(location_data)?;
    let (location_data, restricted_data) = take(size_of::<u8>())(location_data)?;

    let (_, level) = le_f64(level_data)?;
    let (_, charged) = le_u8(charged_data)?;
    let (_, connected) = le_u8(connected_data)?;
    let (_, charger_type) = le_u32(charger_type_data)?;
    let (_, was_connected) = le_u8(was_connected_data)?;

    let (_, reachability) = le_u32(reachability_data)?;
    let (_, thermal_level) = le_i32(thermal_level_data)?;
    let (_, airplane) = le_u8(airplane_data)?;
    let (_, battery_saver) = le_u8(battery_saver_data)?;
    let (_, push_service) = le_u8(push_service_data)?;
    let (_, restricted) = le_u8(restricted_data)?;

    let reachability_str = match reachability {
        2 => "kReachabilityLarge",
        _ => {
            warn!(
                "[macos-unifiedlogs] Unknown reachability value: {}",
                reachability
            );
            "Unknown reachability value"
        }
    };

    let charger_type_str = match charger_type {
        0 => "kChargerTypeUnknown",
        _ => {
            warn!(
                "[macos-unifiedlogs] Unknown charger type value: {}",
                charger_type
            );
            "Unknown charger type value"
        }
    };

    let message = format!(
        r#"{{"thermalLevel": {}, "reachability: "{}", "airplaneMode": {}, "batteryData":{{"wasConnected": {}, "charged": {}, "level": {}, "connected": {}, "chargerType": "{}"}}, "restrictedMode": {}, "batterySaverModeEnabled": {}, "push_service":{}}}"#,
        thermal_level,
        reachability_str,
        lowercase_int_bool(&airplane),
        lowercase_int_bool(&was_connected),
        lowercase_int_bool(&charged),
        level,
        lowercase_int_bool(&connected),
        charger_type_str,
        lowercase_int_bool(&restricted),
        lowercase_int_bool(&battery_saver),
        lowercase_int_bool(&push_service)
    );

    Ok((location_data, message))
}

#[cfg(test)]
mod tests {
    use crate::{
        decoders::location::{
            client_manager_state_tracker_state, daemon_status_type, get_daemon_status_tracker,
            get_location_tracker_state, get_sqlite_data, get_state_tracker_data, io_message,
            location_manager_state_tracker_state, location_tracker_object, sqlite,
            subharvester_identifier, LocationTrackerState,
        },
        util::decode_standard,
    };

    use super::client_authorization_status;

    #[test]
    fn test_client_authorization_status() {
        let test_data = "0";
        let result = client_authorization_status(test_data);

        assert_eq!(result, "Not Determined")
    }

    #[test]
    fn test_daemon_status_type() {
        let test_data = "2";
        let result = daemon_status_type(test_data);

        assert_eq!(result, "Reachability Large")
    }

    #[test]
    fn test_subharvester_identifier() {
        let test_data = "2";
        let result = subharvester_identifier(test_data);

        assert_eq!(result, "Tracks")
    }

    #[test]
    fn test_sqlite() {
        let test_data = "AAAAAA==";
        let result = sqlite(test_data);

        assert_eq!(result, "SQLITE OK")
    }

    #[test]
    fn test_get_sqlite_data() {
        let test_data = "AAAAAA==";
        let decoded_data_result = decode_standard(test_data).unwrap();

        let (_, result) = get_sqlite_data(&decoded_data_result).unwrap();

        assert_eq!(result, "SQLITE OK")
    }

    #[test]
    fn test_client_manager_state_tracker_state() {
        let test_data = "AQAAAAAAAAA=";
        let result = client_manager_state_tracker_state(test_data);

        assert_eq!(
            result,
            "{\"locationRestricted\":false, \"locationServicesenabledStatus\":1}"
        )
    }

    #[test]
    fn test_location_tracker_object() {
        let test_data = LocationTrackerState::default();

        let result = location_tracker_object(&test_data);

        assert_eq!(
            result,
            "{\n            \"distanceFilter\":0, \n            \"desiredAccuracy\":0, \n            \"updatingLocation\":false, \n            \"requestingLocation\":false, \n            \"requestingRanging\":false, \n            \"updatingRanging\":false,\n            \"updatingHeading\":false,\n            \"headingFilter\":0,\n            \"allowsLocationPrompts\":false,\n            \"allowsAlteredAccessoryLocations\":false,\n            \"dynamicAccuracyReductionEnabled\":false,\n            \"previousAuthorizationStatusValid\":false,\n            \"previousAuthorizationStatus\":0,\n            \"limitsPrecision\":false,\n            \"activityType\":0,\n            \"pausesLocationUpdatesAutomatically\":0,\n            \"paused\":false,\n            \"allowsBackgroundLocationUpdates\":false,\n            \"showsBackgroundLocationIndicator\":false,\n            \"allowsMapCorrection\":false,\n            \"batchingLocation\":false,\n            \"updatingVehicleSpeed\":false,\n            \"updatingVehicleHeading\":false,\n            \"matchInfoEnabled\":false,\n            \"groundAltitudeEnabled\":false,\n            \"fusionInfoEnabled\":false,\n            \"courtesyPromptNeeded\":false,\n            \"isAuthorizedForWidgetUpdates\":false,\n        }"
        )
    }

    #[test]
    fn test_get_state_tracker_data() {
        let test_data = "AQAAAAAAAAA=";
        let decoded_data_result = decode_standard(test_data).unwrap();

        let (_, result) = get_state_tracker_data(&decoded_data_result).unwrap();

        assert_eq!(
            result,
            "{\"locationRestricted\":false, \"locationServicesenabledStatus\":1}"
        )
    }

    #[test]
    fn test_location_manager_state_tracker_state() {
        let test_data = "AAAAAAAA8L8AAAAAAABZQAAAAAAAAAAAAAAAAAAA8D8BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAQAAAAAAAAAA";
        let result = location_manager_state_tracker_state(test_data);

        assert_eq!(
            result,
            "{\n            \"distanceFilter\":-1, \n            \"desiredAccuracy\":100, \n            \"updatingLocation\":false, \n            \"requestingLocation\":false, \n            \"requestingRanging\":false, \n            \"updatingRanging\":false,\n            \"updatingHeading\":false,\n            \"headingFilter\":1,\n            \"allowsLocationPrompts\":true,\n            \"allowsAlteredAccessoryLocations\":false,\n            \"dynamicAccuracyReductionEnabled\":false,\n            \"previousAuthorizationStatusValid\":false,\n            \"previousAuthorizationStatus\":0,\n            \"limitsPrecision\":false,\n            \"activityType\":0,\n            \"pausesLocationUpdatesAutomatically\":1,\n            \"paused\":false,\n            \"allowsBackgroundLocationUpdates\":false,\n            \"showsBackgroundLocationIndicator\":false,\n            \"allowsMapCorrection\":true,\n            \"batchingLocation\":false,\n            \"updatingVehicleSpeed\":false,\n            \"updatingVehicleHeading\":false,\n            \"matchInfoEnabled\":false,\n            \"groundAltitudeEnabled\":false,\n            \"fusionInfoEnabled\":false,\n            \"courtesyPromptNeeded\":false,\n            \"isAuthorizedForWidgetUpdates\":false,\n        }"       
        )
    }

    #[test]
    fn test_get_location_tracker_state() {
        let test_data = "AAAAAAAA8L8AAAAAAABZQAAAAAAAAAAAAAAAAAAA8D8BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAQAAAAAAAAAA";
        let decoded_data_result = decode_standard(test_data).unwrap();

        let (_, result) = get_location_tracker_state(&decoded_data_result).unwrap();

        assert_eq!(
            result,
            "{\n            \"distanceFilter\":-1, \n            \"desiredAccuracy\":100, \n            \"updatingLocation\":false, \n            \"requestingLocation\":false, \n            \"requestingRanging\":false, \n            \"updatingRanging\":false,\n            \"updatingHeading\":false,\n            \"headingFilter\":1,\n            \"allowsLocationPrompts\":true,\n            \"allowsAlteredAccessoryLocations\":false,\n            \"dynamicAccuracyReductionEnabled\":false,\n            \"previousAuthorizationStatusValid\":false,\n            \"previousAuthorizationStatus\":0,\n            \"limitsPrecision\":false,\n            \"activityType\":0,\n            \"pausesLocationUpdatesAutomatically\":1,\n            \"paused\":false,\n            \"allowsBackgroundLocationUpdates\":false,\n            \"showsBackgroundLocationIndicator\":false,\n            \"allowsMapCorrection\":true,\n            \"batchingLocation\":false,\n            \"updatingVehicleSpeed\":false,\n            \"updatingVehicleHeading\":false,\n            \"matchInfoEnabled\":false,\n            \"groundAltitudeEnabled\":false,\n            \"fusionInfoEnabled\":false,\n            \"courtesyPromptNeeded\":false,\n            \"isAuthorizedForWidgetUpdates\":false,\n        }"       
        )
    }

    #[test]
    fn test_io_message() {
        let test_data = "3758096981";
        let result = io_message(test_data);

        assert_eq!(result, "SystemPagingOff")
    }

    #[test]
    fn test_get_daemon_status_tracker() {
        let test_data = [
            0, 0, 0, 0, 0, 0, 240, 191, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0,
            255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let (_, result) = get_daemon_status_tracker(&test_data).unwrap();

        assert_eq!(result, "{\"thermalLevel\": -1, \"reachability: \"kReachabilityLarge\", \"airplaneMode\": false, \"batteryData\":{\"wasConnected\": false, \"charged\": false, \"level\": -1, \"connected\": false, \"chargerType\": \"kChargerTypeUnknown\"}, \"restrictedMode\": false, \"batterySaverModeEnabled\": false, \"push_service\":false}")
    }
}
