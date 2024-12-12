// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::util::decode_standard;

use super::{
    bool::{lowercase_bool, lowercase_int_bool},
    DecoderError,
};
use log::warn;
use nom::{
    bytes::complete::take,
    number::complete::{le_f64, le_i32, le_i64, le_u32, le_u8},
    sequence::tuple,
    IResult,
};

#[derive(Debug, Default)]
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
pub(crate) fn client_authorization_status(status: &str) -> Result<String, DecoderError<'_>> {
    let message = match status {
        "0" => "Not Determined",
        "1" => "Restricted",
        "2" => "Denied",
        "3" => "Authorized Always",
        "4" => "Authorized When In Use",
        _ => {
            return Err(DecoderError::Parse {
                input: status.as_bytes(),
                parser_name: "client authorization status",
                message: "Unknown Core Location client authorization status",
            });
        }
    };
    Ok(message.to_string())
}

/// Convert Core Location Daemon Status type to string
pub(crate) fn daemon_status_type(status: &str) -> Result<String, DecoderError<'_>> {
    // Found in dyldcache liblog
    let message = match status {
        "0" => "Reachability Unavailable",
        "1" => "Reachability Small",
        "2" => "Reachability Large",
        "56" => "Reachability Unachievable",
        _ => {
            return Err(DecoderError::Parse {
                input: status.as_bytes(),
                parser_name: "daemon status type",
                message: "Unknown Core Location daemon status type",
            });
        }
    };
    Ok(message.to_string())
}

/// Convert Core Location Subhaverester id to string
pub(crate) fn subharvester_identifier(status: &str) -> Result<String, DecoderError<'_>> {
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
            return Err(DecoderError::Parse {
                input: status.as_bytes(),
                parser_name: "subharvester identifier",
                message: "Unknown Core Location subhaverster identifier type",
            });
        }
    };
    Ok(message.to_string())
}

/// Convert Core Location SQLITE code to string
pub(crate) fn sqlite_location(input: &str) -> Result<&'static str, DecoderError<'_>> {
    let decoded_data = decode_standard(input).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "sqlite location",
        message: "Failed to base64 decode sqlite details",
    })?;

    let (_, result) = get_sqlite_data(&decoded_data).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "sqlite location",
        message: "Failed to get sqlite error",
    })?;

    Ok(result)
}

/// Get the SQLITE error message
fn get_sqlite_data(input: &[u8]) -> IResult<&[u8], &'static str> {
    let (input, sqlite_code) = le_u32(input)?;

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

    Ok((input, message))
}

/// Parse the manager tracker state data
pub(crate) fn client_manager_state_tracker_state(input: &str) -> Result<String, DecoderError<'_>> {
    let decoded_data = decode_standard(input).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "client manager state tracker state",
        message: "Failed to base64 decode client manager tracker state",
    })?;

    let (_, result) = get_state_tracker_data(&decoded_data).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "client manager state tracker state",
        message: "Failed to get client tracker data",
    })?;

    Ok(result)
}

/// Get the tracker data
pub(crate) fn get_state_tracker_data(input: &[u8]) -> IResult<&[u8], String> {
    let (input, (location_enabled, location_restricted)) = tuple((le_u32, le_u32))(input)?;
    Ok((
        input,
        format!(
            "{{\"locationRestricted\":{}, \"locationServicesenabledStatus\":{}}}",
            lowercase_bool(&format!("{}", location_restricted)),
            location_enabled
        ),
    ))
}

/// Parse location tracker state data
pub(crate) fn location_manager_state_tracker_state(
    input: &str,
) -> Result<String, DecoderError<'_>> {
    let decoded_data = decode_standard(input).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "location manager state tracker state",
        message: "Failed to base64 decode logon manager trackder data",
    })?;

    let (_, result) =
        get_location_tracker_state(&decoded_data).map_err(|_| DecoderError::Parse {
            input: input.as_bytes(),
            parser_name: "location manager state tracker state",
            message: "Failed to get logon manager tracker data",
        })?;

    Ok(result)
}

/// Get the location state data
pub(crate) fn get_location_tracker_state(input: &[u8]) -> nom::IResult<&[u8], String> {
    // https://github.com/cmsj/ApplePrivateHeaders/blob/main/macOS/11.3/System/Library/Frameworks/CoreLocation.framework/Versions/A/CoreLocation/CoreLocation-Structs.h and in dyldcache

    // Padding? Reserved?
    const UNKNOWN_DATA_LENGTH: usize = 3;
    // padding? Reserved?
    const UNKONWN_DATA_LENGTH2: usize = 7;

    let (
        input,
        (
            distance_filter,
            desired_accuracy,
            updating_location,
            requesting_location,
            requesting_ranging,
            updating_ranging,
            updating_heading,
        ),
    ) = tuple((le_f64, le_f64, le_u8, le_u8, le_u8, le_u8, le_u8))(input)?;

    let (
        input,
        (
            _unknown,
            heading_filter,
            allows_location_prompts,
            allows_altered_locations,
            dynamic_accuracy,
        ),
    ) = tuple((take(UNKNOWN_DATA_LENGTH), le_f64, le_u8, le_u8, le_u8))(input)?;

    let (
        input,
        (
            previous_authorization_status_valid,
            previous_authorization_status,
            limits_precision,
            _unknown2,
            activity_type,
            pauses_location_updates,
        ),
    ) = tuple((
        le_u8,
        le_i32,
        le_u8,
        take(UNKONWN_DATA_LENGTH2),
        le_i64,
        le_i32,
    ))(input)?;

    let (
        input,
        (paused, allows_background_updates, shows_background_location, allows_map_correction),
    ) = tuple((le_u8, le_u8, le_u8, le_u8))(input)?;

    let location_data = input;

    let tracker = LocationTrackerState {
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
        ..Default::default()
    };

    // Sometimes location data only has 64 bytes of data. Seen only on Catalina. Though this might be a setting configuration?
    // All other systems have 72 bytes of location data even systems before Catalina (ex: Mojave)
    // Return early if we only have 64 bytes to work with
    const CATALINA_SIZE: usize = 64;
    if input.len() == CATALINA_SIZE {
        return Ok((location_data, location_tracker_object(&tracker)));
    }

    let (
        input,
        (
            batching_location,
            updating_vehicle_speed,
            updating_vehicle_heading,
            match_info,
            ground_altitude,
            fusion_info,
            courtesy_prompt,
            is_authorized_for_widgets,
        ),
    ) = tuple((le_u8, le_u8, le_u8, le_u8, le_u8, le_u8, le_u8, le_u8))(input)?;

    let tracker = LocationTrackerState {
        batching_location,
        updating_vehicle_speed,
        updating_vehicle_heading,
        match_info,
        ground_altitude,
        fusion_info,
        courtesy_prompt,
        is_authorized_for_widgets,
        ..tracker
    };

    Ok((input, location_tracker_object(&tracker)))
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
        lowercase_int_bool(tracker.updating_location),
        lowercase_int_bool(tracker.requesting_location),
        lowercase_int_bool(tracker.requesting_ranging),
        lowercase_int_bool(tracker.updating_ranging),
        lowercase_int_bool(tracker.updating_heading),
        tracker.heading_filter,
        lowercase_int_bool(tracker.allows_location_prompts),
        lowercase_int_bool(tracker.allows_altered_locations),
        lowercase_int_bool(tracker.dynamic_accuracy),
        lowercase_int_bool(tracker.previous_authorization_status_valid),
        tracker.previous_authorization_status,
        lowercase_int_bool(tracker.limits_precision),
        tracker.activity_type,
        tracker.pauses_location_updates,
        lowercase_int_bool(tracker.paused),
        lowercase_int_bool(tracker.allows_background_updates),
        lowercase_int_bool(tracker.shows_background_location),
        lowercase_int_bool(tracker.allows_map_correction),
        lowercase_int_bool(tracker.batching_location),
        lowercase_int_bool(tracker.updating_vehicle_speed),
        lowercase_int_bool(tracker.updating_vehicle_heading),
        lowercase_int_bool(tracker.match_info),
        lowercase_int_bool(tracker.ground_altitude),
        lowercase_int_bool(tracker.fusion_info),
        lowercase_int_bool(tracker.courtesy_prompt),
        lowercase_int_bool(tracker.is_authorized_for_widgets),
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
pub(crate) fn get_daemon_status_tracker(input: &[u8]) -> nom::IResult<&[u8], String> {
    // https://gist.github.com/razvand/578f94748b624f4d47c1533f5a02b095
    const RESERVED_SIZE: usize = 9;

    let (
        location_data,
        (
            level,
            charged,
            connected,
            charger_type,
            was_connected,
            _reserved,
            reachability,
            thermal_level,
            airplane,
            battery_saver,
            push_service,
            restricted,
        ),
    ) = tuple((
        le_f64,
        le_u8,
        le_u8,
        le_u32,
        le_u8,
        take(RESERVED_SIZE),
        le_u32,
        le_i32,
        le_u8,
        le_u8,
        le_u8,
        le_u8,
    ))(input)?;

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
        lowercase_int_bool(airplane),
        lowercase_int_bool(was_connected),
        lowercase_int_bool(charged),
        level,
        lowercase_int_bool(connected),
        charger_type_str,
        lowercase_int_bool(restricted),
        lowercase_int_bool(battery_saver),
        lowercase_int_bool(push_service)
    );

    Ok((location_data, message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::decode_standard;

    #[test]
    fn test_client_authorization_status() {
        let test_data = "0";
        let result = client_authorization_status(test_data).unwrap();

        assert_eq!(result, "Not Determined")
    }

    #[test]
    fn test_daemon_status_type() {
        let test_data = "2";
        let result = daemon_status_type(test_data).unwrap();

        assert_eq!(result, "Reachability Large")
    }

    #[test]
    fn test_subharvester_identifier() {
        let test_data = "2";
        let result = subharvester_identifier(test_data).unwrap();

        assert_eq!(result, "Tracks")
    }

    #[test]
    fn test_sqlite() {
        let test_data = "AAAAAA==";
        let result = sqlite_location(test_data).unwrap();

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
        let result = client_manager_state_tracker_state(test_data).unwrap();

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
        let result = location_manager_state_tracker_state(test_data).unwrap();

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
