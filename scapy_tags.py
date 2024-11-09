# Author: Pieter Robyns, 2017
# License: GNU GENERAL PUBLIC LICENSE, Version 3, 29 June 2007
# See LICENSE in this Git repository for the full license description

TAG_SSID                      = 0
TAG_SUPP_RATES                = 1
TAG_FH_PARAMETER              = 2
TAG_DS_PARAMETER              = 3
TAG_CF_PARAMETER              = 4
TAG_TIM                       = 5
TAG_IBSS_PARAMETER            = 6
TAG_COUNTRY_INFO              = 7
TAG_FH_HOPPING_PARAMETER      = 8
TAG_FH_HOPPING_TABLE          = 9
TAG_REQUEST                  = 10
TAG_QBSS_LOAD                = 11
TAG_EDCA_PARAM_SET           = 12
TAG_TSPEC                    = 13
TAG_TCLAS                    = 14
TAG_SCHEDULE                 = 15
TAG_CHALLENGE_TEXT           = 16

TAG_POWER_CONSTRAINT         = 32
TAG_POWER_CAPABILITY         = 33
TAG_TPC_REQUEST              = 34
TAG_TPC_REPORT               = 35
TAG_SUPPORTED_CHANNELS       = 36
TAG_CHANNEL_SWITCH_ANN       = 37
TAG_MEASURE_REQ              = 38
TAG_MEASURE_REP              = 39
TAG_QUIET                    = 40
TAG_IBSS_DFS                 = 41
TAG_ERP_INFO                 = 42
TAG_TS_DELAY                 = 43
TAG_TCLAS_PROCESS            = 44
TAG_HT_CAPABILITY            = 45 # /* IEEE Stc 802.11n/D2.0 */
TAG_QOS_CAPABILITY           = 46
TAG_ERP_INFO_OLD             = 47 # /* IEEE Std 802.11g/D4.0 */
TAG_RSN_IE                   = 48
## /* Reserved 49 */
TAG_EXT_SUPP_RATES           = 50
TAG_AP_CHANNEL_REPORT        = 51
TAG_NEIGHBOR_REPORT          = 52
TAG_RCPI                     = 53
TAG_MOBILITY_DOMAIN          = 54  # /* IEEE Std 802.11r-2008 */
TAG_FAST_BSS_TRANSITION      = 55  # /* IEEE Std 802.11r-2008 */
TAG_TIMEOUT_INTERVAL         = 56  # /* IEEE Std 802.11r-2008 */
TAG_RIC_DATA                 = 57  # /* IEEE Std 802.11r-2008 */
TAG_DSE_REG_LOCATION         = 58
TAG_SUPPORTED_REGULATORY_CLASSES           = 59 # /* IEEE Std 802.11w-2009 */
TAG_EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT   = 60 # /* IEEE Std 802.11w-2009 */
TAG_HT_INFO                  = 61  # /* IEEE Stc 802.11n/D2.0 */
TAG_SECONDARY_CHANNEL_OFFSET = 62  # /* IEEE Stc 802.11n/D1.10/D2.0 */
TAG_BSS_AVG_ACCESS_DELAY     = 63
TAG_ANTENNA                  = 64
TAG_RSNI                     = 65
TAG_MEASURE_PILOT_TRANS      = 66
TAG_BSS_AVB_ADM_CAPACITY     = 67
TAG_IE_68_CONFLICT           = 68  # /* Conflict: WAPI Vs. IEEE */
TAG_WAPI_PARAM_SET           = 68
TAG_BSS_AC_ACCESS_DELAY      = 68
TAG_TIME_ADV                 = 69  # /* IEEE Std 802.11p-2010 */
TAG_RM_ENABLED_CAPABILITY    = 70
TAG_MULTIPLE_BSSID           = 71
TAG_20_40_BSS_CO_EX          = 72  # /* IEEE P802.11n/D6.0 */
TAG_20_40_BSS_INTOL_CH_REP   = 73  # /* IEEE P802.11n/D6.0 */
TAG_OVERLAP_BSS_SCAN_PAR     = 74  # /* IEEE P802.11n/D6.0 */
TAG_RIC_DESCRIPTOR           = 75  # /* IEEE Std 802.11r-2008 */
TAG_MMIE                     = 76  # /* IEEE Std 802.11w-2009 */
TAG_EVENT_REQUEST            = 78
TAG_EVENT_REPORT             = 79
TAG_DIAGNOSTIC_REQUEST       = 80
TAG_DIAGNOSTIC_REPORT        = 81
TAG_LOCATION_PARAMETERS      = 82
TAG_NO_BSSID_CAPABILITY      = 83
TAG_SSID_LIST                = 84
TAG_MULTIPLE_BSSID_INDEX     = 85
TAG_FMS_DESCRIPTOR           = 86
TAG_FMS_REQUEST              = 87
TAG_FMS_RESPONSE             = 88
TAG_QOS_TRAFFIC_CAPABILITY   = 89
TAG_BSS_MAX_IDLE_PERIOD      = 90
TAG_TFS_REQUEST              = 91
TAG_TFS_RESPONSE             = 92
TAG_WNM_SLEEP_MODE           = 93
TAG_TIM_BROADCAST_REQUEST    = 94
TAG_TIM_BROADCAST_RESPONSE   = 95
TAG_COLLOCATED_INTER_REPORT  = 96
TAG_CHANNEL_USAGE            = 97
TAG_TIME_ZONE                = 98  # /* IEEE Std 802.11v-2011 */
TAG_DMS_REQUEST              = 99
TAG_DMS_RESPONSE            = 100
TAG_LINK_IDENTIFIER         = 101  # /* IEEE Std 802.11z-2010 */
TAG_WAKEUP_SCHEDULE         = 102  # /* IEEE Std 802.11z-2010 */
TAG_CHANNEL_SWITCH_TIMING   = 104  # /* IEEE Std 802.11z-2010 */
TAG_PTI_CONTROL             = 105  # /* IEEE Std 802.11z-2010 */
TAG_PU_BUFFER_STATUS        = 106  # /* IEEE Std 802.11z-2010 */
TAG_INTERWORKING            = 107  # /* IEEE Std 802.11u-2011 */
TAG_ADVERTISEMENT_PROTOCOL  = 108  # /* IEEE Std 802.11u-2011 */
TAG_EXPIDITED_BANDWIDTH_REQ = 109  # /* IEEE Std 802.11u-2011 */
TAG_QOS_MAP_SET             = 110  # /* IEEE Std 802.11u-2011 */
TAG_ROAMING_CONSORTIUM      = 111  # /* IEEE Std 802.11u-2011 */
TAG_EMERGENCY_ALERT_ID      = 112  # /* IEEE Std 802.11u-2011 */
TAG_MESH_CONFIGURATION      = 113  # /* IEEE Std 802.11s-2011 */
TAG_MESH_ID                 = 114  # /* IEEE Std 802.11s-2011 */
TAG_MESH_LINK_METRIC_REPORT = 115
TAG_CONGESTION_NOTIFICATION = 116
TAG_MESH_PEERING_MGMT       = 117  # /* IEEE Std 802.11s-2011 */
TAG_MESH_CHANNEL_SWITCH     = 118
TAG_MESH_AWAKE_WINDOW       = 119
TAG_BEACON_TIMING           = 120
TAG_MCCAOP_SETUP_REQUEST    = 121
TAG_MCCAOP_SETUP_REPLY      = 122
TAG_MCCAOP_ADVERTISSEMENT   = 123
TAG_MCCAOP_TEARDOWN         = 124
TAG_GANN                    = 125
TAG_RANN                    = 126  # /* IEEE Std 802.11s-2011 */
TAG_EXTENDED_CAPABILITIES   = 127  # /* IEEE Stc 802.11n/D1.10/D2.0 */
TAG_AGERE_PROPRIETARY       = 128
TAG_MESH_PREQ               = 130  # /* IEEE Std 802.11s-2011 */
TAG_MESH_PREP               = 131  # /* IEEE Std 802.11s-2011 */
TAG_MESH_PERR               = 132  # /* IEEE Std 802.11s-2011 */
TAG_CISCO_CCX1_CKIP         = 133  # /* Cisco Compatible eXtensions v1 */
TAG_CISCO_CCX2              = 136  # /* Cisco Compatible eXtensions v2 */
TAG_PXU                     = 137
TAG_PXUC                    = 138
TAG_AUTH_MESH_PEERING_EXCH  = 139
TAG_MIC                     = 140
TAG_DESTINATION_URI         = 141
TAG_U_APSD_COEX             = 142

# 802.11 2020 - Page 943
TAG_DMG_WAKEUP_SCHEDULE     = 143
TAG_EXTENDED_SCHEDULE       = 144
TAG_STA_AVAILABILITY        = 145
TAG_DMG_TSPEC               = 146
TAG_DMG_ATTRIBUTE           = 147
TAG_DMG_CAPABILITIES        = 148
# end 802.11 2020

TAG_CISCO_CCX3              = 149  # /* Cisco Compatible eXtensions v3 */
TAG_CISCO_UNKNOWN_96        = 150  # /* Cisco Compatible eXtensions */

# 802.11 2020 - Page 943
TAG_DMG_OPERATION           = 151
TAG_DMG_BSS_PARAM_CHANGE    = 152
TAG_DMG_BEAM_REFINEMENT     = 153
TAG_CHANNEL_MEASUREMENT_FEEDBACK = 154

TAG_AWAKE_WINDOW            = 157
TAG_MULTI_BAND              = 158
TAG_ADDBA_EXT               = 159
TAG_NEXT_PCP_LIST           = 160
TAG_PCP_HANDOVER            = 161
TAG_DMG_LINK_MARGIN         = 162
TAG_SWITCHING_STREAM        = 163
TAG_SESSION_TRANSITION      = 164

TAG_CLUSTER_REPORT          = 166
TAG_RELAY_CAPABILITY        = 167
TAG_RELAY_TRANSFER_PARAM    = 168
TAG_BEAM_LINK_MAINT         = 169
TAG_MULTIPLE_MAC_SUBLAYERS  = 170
TAG_U_PID                   = 171
TAG_DMG_LINK_ADAPTATION_ACK = 172
# end 802.11 2020

TAG_SYMBOL_PROPRIETARY      = 173
TAG_MCCAOP_ADVERTISSEMENT_OV= 174

# 802.11 2020 - Page 945
TAG_QUIET_PERIOD_REQ        = 175

TAG_QUIET_PERIOD_RESP       = 177

TAG_QMF_POLICY              = 181
TAG_ECAPC_POLICY            = 182
TAG_CLUSTER_TIME_OFFSET     = 183
TAG_INTRA_ACCESS_CATEGORY_PRIORITY = 184
TAG_SCS_DESCRIPTOR          = 185
TAG_QLOAD_REPORT            = 186
TAG_HCCA_TXOP_UPDATE_COUNT  = 187
TAG_HIGHER_LAYER_STREAM_ID  = 188
TAG_GCR_GROUP_ADDRESS       = 189
TAG_ANTENNA_SECTOR_ID_PATTERN = 190
# end 802.11 2020

TAG_VHT_CAPABILITY          = 191  # /* IEEE Std 802.11ac/D3.1 */
TAG_VHT_OPERATION           = 192  # /* IEEE Std 802.11ac/D3.1 */

# 802.11 2020 - Page 945
TAG_EXTENDED_BSS_LOAD       = 193
TAG_WIDE_BW_CHANNEL_SWITCH  = 194
# end 802.11 2020

TAG_VHT_TX_PWR_ENVELOPE     = 195  # /* IEEE Std 802.11ac/D5.0 */

# 802.11 2020 - Page 945
TAG_CHANNEL_SWITCH_WRAPPER  = 196
TAG_AID                     = 197
TAG_QUIET_CHANNEL           = 198
TAG_OPERATING_MODE_NOTIFICATION = 199
TAG_UPSIM                   = 200
TAG_REDUCED_NEIGHBOR_REPORT = 201
TAG_TVHT_OPERATION          = 202

TAG_DEVICE_LOCATION         = 204
TAG_WHITE_SPACE_MAP         = 205
TAG_FINE_TIMING_MEASUREMENT_PARAMETERS = 206
TAG_S1G_OPEN_LOOP_LINK_MARGIN_INDEX = 207
TAG_RPS                     = 208
TAG_PAGE_SLICE              = 209
TAG_AID_REQUEST             = 210
TAG_AID_RESPONSE            = 211
TAG_S1G_SECTOR_OPERATION    = 212
TAG_S1G_BEACON_COMPATIBILITY = 213
TAG_SHORT_BEACON_INTERVAL   = 214
TAG_CHANGE_SEQUENCE         = 215
TAG_TWT                     = 216
TAG_S1G_CAPABILITIES        = 217

TAG_SUBCHANNEL_SELECTIVE_TRANSMISSION = 220
# end 802.11 2020

TAG_VENDOR_SPECIFIC_IE      = 221

# 802.11 2020 - Page 946
TAG_AUTHENTICATION_CONTROL      = 222
TAG_TSF_TIMER_ACCURACY          = 223
TAG_S1G_RELAY                   = 224
TAG_REACHABLE_ADDRESS           = 225
TAG_S1G_RELAY_DISCOVERY         = 226

TAG_AID_ANNOUNCEMENT            = 228
TAG_PV1_PROBE_RESPONSE_OPTION   = 229
TAG_EL_OPERATION                = 230
TAG_SECTORIZED_GROUP_ID_LIST    = 231
TAG_S1G_OPERATION               = 232
TAG_HEADER_COMPRESSION          = 233
TAG_SST_OPERATION               = 234
TAG_MAD                         = 235
TAG_S1G_RELAY_ACTIVATION        = 236
TAG_CAG_NUMBER                  = 237

TAG_AP_CSN                      = 239
TAG_FILS_INDICATION             = 240
TAG_DILS                        = 241
TAG_FRAGMENT                    = 242

TAG_RSN_EXTENSION               = 244
# end 802.11 2020

elt_id_map = {
   TAG_SSID:                                 "SSID parameter set" ,
   TAG_SUPP_RATES:                           "Supported Rates" ,
   TAG_FH_PARAMETER:                         "FH Parameter set" ,
   TAG_DS_PARAMETER:                         "DS Parameter set" ,
   TAG_CF_PARAMETER:                         "CF Parameter set" ,
   TAG_TIM:                                  "Traffic Indication Map (TIM)" ,
   TAG_IBSS_PARAMETER:                       "IBSS Parameter set" ,
   TAG_COUNTRY_INFO:                         "Country Information" ,
   TAG_FH_HOPPING_PARAMETER:                 "Hopping Pattern Parameters" ,
   TAG_FH_HOPPING_TABLE:                     "Hopping Pattern Table" ,
   TAG_REQUEST:                              "Request" ,
   TAG_QBSS_LOAD:                            "QBSS Load Element" ,
   TAG_EDCA_PARAM_SET:                       "EDCA Parameter Set" ,
   TAG_TSPEC:                                "Traffic Specification" ,
   TAG_TCLAS:                                "Traffic Classification" ,
   TAG_SCHEDULE:                             "Schedule" ,
   TAG_CHALLENGE_TEXT:                       "Challenge text" ,
   TAG_POWER_CONSTRAINT:                     "Power Constraint" ,
   TAG_POWER_CAPABILITY:                     "Power Capability" ,
   TAG_TPC_REQUEST:                          "TPC Request" ,
   TAG_TPC_REPORT:                           "TPC Report" ,
   TAG_SUPPORTED_CHANNELS:                   "Supported Channels" ,
   TAG_CHANNEL_SWITCH_ANN:                   "Channel Switch Announcement" ,
   TAG_MEASURE_REQ:                          "Measurement Request" ,
   TAG_MEASURE_REP:                          "Measurement Report" ,
   TAG_QUIET:                                "Quiet" ,
   TAG_IBSS_DFS:                             "IBSS DFS" ,
   TAG_ERP_INFO:                             "ERP Information" ,
   TAG_TS_DELAY:                             "TS Delay" ,
   TAG_TCLAS_PROCESS:                        "TCLAS Processing" ,
   TAG_HT_CAPABILITY:                        "HT Capabilities" ,
   TAG_QOS_CAPABILITY:                       "QoS Capability" ,
   TAG_ERP_INFO_OLD:                         "ERP Information" , # /* Reserved... */
   TAG_RSN_IE:                               "RSN Information" ,
   TAG_EXT_SUPP_RATES:                       "Extended Supported Rates" ,
   TAG_AP_CHANNEL_REPORT:                    "AP Channel Report" ,
   TAG_NEIGHBOR_REPORT:                      "Neighbor Report" ,
   TAG_RCPI:                                 "RCPI" ,
   TAG_MOBILITY_DOMAIN:                      "Mobility Domain" ,
   TAG_FAST_BSS_TRANSITION:                  "Fast BSS Transition" ,
   TAG_TIMEOUT_INTERVAL:                     "Timeout Interval" ,
   TAG_RIC_DATA:                             "RIC Data" ,
   TAG_DSE_REG_LOCATION:                     "DSE Registered Location" ,
   TAG_SUPPORTED_REGULATORY_CLASSES:         "Supported Regulatory Classes" ,
   TAG_EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT: "Extended Channel Switch Announcement" ,
   TAG_HT_INFO:                              "HT Information" ,
   TAG_SECONDARY_CHANNEL_OFFSET:             "Secondary Channel Offset" ,
   TAG_BSS_AVG_ACCESS_DELAY:                 "BSS Average Access Delay" ,
   TAG_ANTENNA:                              "Antenna" ,
   TAG_RSNI:                                 "RSNI" ,
   TAG_MEASURE_PILOT_TRANS:                  "Measurement Pilot Transmission" ,
   TAG_BSS_AVB_ADM_CAPACITY:                 "BSS Available Admission Capacity" ,
   TAG_IE_68_CONFLICT:                       "BSS AC Access Delay/WAPI Parameter Set" ,
   TAG_TIME_ADV:                             "Time Advertisement" ,
   TAG_RM_ENABLED_CAPABILITY:                "RM Enabled Capabilities" ,
   TAG_MULTIPLE_BSSID:                       "Multiple BSSID" ,
   TAG_20_40_BSS_CO_EX:                      "20/40 BSS Coexistence" ,
   TAG_20_40_BSS_INTOL_CH_REP:               "20/40 BSS Intolerant Channel Report" ,   # /* IEEE P802.11n/D6.0 */
   TAG_OVERLAP_BSS_SCAN_PAR:                 "Overlapping BSS Scan Parameters" ,       # /* IEEE P802.11n/D6.0 */
   TAG_RIC_DESCRIPTOR:                       "RIC Descriptor" ,
   TAG_MMIE:                                 "Management MIC" ,
   TAG_EVENT_REQUEST:                        "Event Request" ,
   TAG_EVENT_REPORT:                         "Event Report" ,
   TAG_DIAGNOSTIC_REQUEST:                   "Diagnostic Request" ,
   TAG_DIAGNOSTIC_REPORT:                    "Diagnostic Report" ,
   TAG_LOCATION_PARAMETERS:                  "Location Parameters" ,
   TAG_NO_BSSID_CAPABILITY:                  "Non Transmitted BSSID Capability" ,
   TAG_SSID_LIST:                            "SSID List" ,
   TAG_MULTIPLE_BSSID_INDEX:                 "Multiple BSSID Index" ,
   TAG_FMS_DESCRIPTOR:                       "FMS Descriptor" ,
   TAG_FMS_REQUEST:                          "FMS Request" ,
   TAG_FMS_RESPONSE:                         "FMS Response" ,
   TAG_QOS_TRAFFIC_CAPABILITY:               "QoS Traffic Capability" ,
   TAG_BSS_MAX_IDLE_PERIOD:                  "BSS Max Idle Period" ,
   TAG_TFS_REQUEST:                          "TFS Request" ,
   TAG_TFS_RESPONSE:                         "TFS Response" ,
   TAG_WNM_SLEEP_MODE:                       "WNM-Sleep Mode" ,
   TAG_TIM_BROADCAST_REQUEST:                "TIM Broadcast Request" ,
   TAG_TIM_BROADCAST_RESPONSE:               "TIM Broadcast Response" ,
   TAG_COLLOCATED_INTER_REPORT:              "Collocated Interference Report" ,
   TAG_CHANNEL_USAGE:                        "Channel Usage" ,
   TAG_TIME_ZONE:                            "Time Zone" ,
   TAG_DMS_REQUEST:                          "DMS Request" ,
   TAG_DMS_RESPONSE:                         "DMS Response" ,
   TAG_LINK_IDENTIFIER:                      "Link Identifier" ,
   TAG_WAKEUP_SCHEDULE:                      "Wakeup Schedule" ,
   TAG_CHANNEL_SWITCH_TIMING:                "Channel Switch Timing" ,
   TAG_PTI_CONTROL:                          "PTI Control" ,
   TAG_PU_BUFFER_STATUS:                     "PU Buffer Status" ,
   TAG_INTERWORKING:                         "Interworking" ,
   TAG_ADVERTISEMENT_PROTOCOL:               "Advertisement Protocol",
   TAG_EXPIDITED_BANDWIDTH_REQ:              "Expedited Bandwidth Request" ,
   TAG_QOS_MAP_SET:                          "QoS Map Set" ,
   TAG_ROAMING_CONSORTIUM:                   "Roaming Consortium" ,
   TAG_EMERGENCY_ALERT_ID:                   "Emergency Alert Identifier" ,
   TAG_MESH_CONFIGURATION:                   "Mesh Configuration" ,
   TAG_MESH_ID:                              "Mesh ID" ,
   TAG_MESH_LINK_METRIC_REPORT:              "Mesh Link Metric Report" ,
   TAG_CONGESTION_NOTIFICATION:              "Congestion Notification" ,
   TAG_MESH_PEERING_MGMT:                    "Mesh Peering Management" ,
   TAG_MESH_CHANNEL_SWITCH:                  "Mesh Channel Switch Parameters" ,
   TAG_MESH_AWAKE_WINDOW:                    "Mesh Awake Windows" ,
   TAG_BEACON_TIMING:                        "Beacon Timing" ,
   TAG_MCCAOP_SETUP_REQUEST:                 "MCCAOP Setup Request" ,
   TAG_MCCAOP_SETUP_REPLY:                   "MCCAOP SETUP Reply" ,
   TAG_MCCAOP_ADVERTISSEMENT:                "MCCAOP Advertissement" ,
   TAG_MCCAOP_TEARDOWN:                      "MCCAOP Teardown" ,
   TAG_GANN:                                 "Gate Announcemen" ,
   TAG_RANN:                                 "Root Announcement" ,
   TAG_EXTENDED_CAPABILITIES:                "Extended Capabilities" ,
   TAG_AGERE_PROPRIETARY:                    "Agere Proprietary" ,
   TAG_MESH_PREQ:                            "Path Request" ,
   TAG_MESH_PREP:                            "Path Reply" ,
   TAG_MESH_PERR:                            "Path Error" ,
   TAG_CISCO_CCX1_CKIP:                      "Cisco CCX1 CKIP + Device Name" ,
   TAG_CISCO_CCX2:                           "Cisco CCX2" ,
   TAG_PXU:                                  "Proxy Update" ,
   TAG_PXUC:                                 "Proxy Update Confirmation",
   TAG_AUTH_MESH_PEERING_EXCH:               "Authenticated Mesh Peering Exchange" ,
   TAG_MIC:                                  "MIC (Message Integrity Code)" ,
   TAG_DESTINATION_URI:                      "Destination URI" ,
   TAG_U_APSD_COEX:                          "U-APSD Coexistence" ,
        TAG_DMG_WAKEUP_SCHEDULE: "DMG_WAKEUP_SCHEDULE", 
        TAG_EXTENDED_SCHEDULE: "EXTENDED_SCHEDULE", 
        TAG_STA_AVAILABILITY: "STA_AVAILABILITY", 
        TAG_DMG_TSPEC: "DMG_TSPEC", 
        TAG_DMG_ATTRIBUTE: "DMG_ATTRIBUTE", 
        TAG_DMG_CAPABILITIES: "DMG_CAPABILITIES", 
   TAG_CISCO_CCX3:                           "Cisco Unknown 95" ,
   TAG_CISCO_UNKNOWN_96:                     "Cisco Unknown 96" ,
   
    TAG_DMG_OPERATION: "DMG_OPERATION", 
    TAG_DMG_BSS_PARAM_CHANGE: "DMG_BSS_PARAM_CHANGE", 
    TAG_DMG_BEAM_REFINEMENT: "DMG_BEAM_REFINEMENT", 
    TAG_CHANNEL_MEASUREMENT_FEEDBACK: "CHANNEL_MEASUREMENT_FEEDBACK", 
    TAG_AWAKE_WINDOW: "AWAKE_WINDOW", 
    TAG_MULTI_BAND: "MULTI_BAND", 
    TAG_ADDBA_EXT: "ADDBA_EXT", 
    TAG_NEXT_PCP_LIST: "NEXT_PCP_LIST", 
    TAG_PCP_HANDOVER: "PCP_HANDOVER", 
    TAG_DMG_LINK_MARGIN: "DMG_LINK_MARGIN", 
    TAG_SWITCHING_STREAM: "SWITCHING_STREAM", 
    TAG_SESSION_TRANSITION: "SESSION_TRANSITION", 
    TAG_CLUSTER_REPORT: "CLUSTER_REPORT", 
    TAG_RELAY_CAPABILITY: "RELAY_CAPABILITY", 
    TAG_RELAY_TRANSFER_PARAM: "RELAY_TRANSFER_PARAM", 
    TAG_BEAM_LINK_MAINT: "BEAM_LINK_MAINT", 
    TAG_MULTIPLE_MAC_SUBLAYERS: "MULTIPLE_MAC_SUBLAYERS", 
    TAG_U_PID: "U_PID", 
    TAG_DMG_LINK_ADAPTATION_ACK: "DMG_LINK_ADAPTATION_ACK", 

   TAG_SYMBOL_PROPRIETARY:                   "Symbol Proprietary" ,
   TAG_MCCAOP_ADVERTISSEMENT_OV:             "MCCAOP Advertisement Overview" ,
   
        TAG_QUIET_PERIOD_REQ: "QUIET_PERIOD_REQ", 
        TAG_QUIET_PERIOD_RESP: "QUIET_PERIOD_RESP", 
        TAG_QMF_POLICY: "QMF_POLICY", 
        TAG_ECAPC_POLICY: "ECAPC_POLICY", 
        TAG_CLUSTER_TIME_OFFSET: "CLUSTER_TIME_OFFSET", 
        TAG_INTRA_ACCESS_CATEGORY_PRIORITY: "INTRA_ACCESS_CATEGORY_PRIORITY", 
        TAG_SCS_DESCRIPTOR: "SCS_DESCRIPTOR", 
        TAG_QLOAD_REPORT: "QLOAD_REPORT", 
        TAG_HCCA_TXOP_UPDATE_COUNT: "HCCA_TXOP_UPDATE_COUNT", 
        TAG_HIGHER_LAYER_STREAM_ID: "HIGHER_LAYER_STREAM_ID", 
        TAG_GCR_GROUP_ADDRESS: "GCR_GROUP_ADDRESS", 
        TAG_ANTENNA_SECTOR_ID_PATTERN: "ANTENNA_SECTOR_ID_PATTERN", 

   TAG_VHT_CAPABILITY:                       "VHT Capabilities" ,
   TAG_VHT_OPERATION:                        "VHT Operation" ,
   
        TAG_EXTENDED_BSS_LOAD: "EXTENDED_BSS_LOAD", 
        TAG_WIDE_BW_CHANNEL_SWITCH: "WIDE_BW_CHANNEL_SWITCH",   
   
   TAG_VHT_TX_PWR_ENVELOPE:                  "VHT Tx Power Envelope" ,
   
        TAG_CHANNEL_SWITCH_WRAPPER: "CHANNEL_SWITCH_WRAPPER", 
        TAG_AID: "AID", 
        TAG_QUIET_CHANNEL: "QUIET_CHANNEL", 
        TAG_OPERATING_MODE_NOTIFICATION: "OPERATING_MODE_NOTIFICATION", 
        TAG_UPSIM: "UPSIM", 
        TAG_REDUCED_NEIGHBOR_REPORT: "REDUCED_NEIGHBOR_REPORT", 
        TAG_TVHT_OPERATION: "TVHT_OPERATION", 
        TAG_DEVICE_LOCATION: "DEVICE_LOCATION", 
        TAG_WHITE_SPACE_MAP: "WHITE_SPACE_MAP", 
        TAG_FINE_TIMING_MEASUREMENT_PARAMETERS: "FINE_TIMING_MEASUREMENT_PARAMETERS", 
        TAG_S1G_OPEN_LOOP_LINK_MARGIN_INDEX: "S1G_OPEN_LOOP_LINK_MARGIN_INDEX", 
        TAG_RPS: "RPS", 
        TAG_PAGE_SLICE: "PAGE_SLICE", 
        TAG_AID_REQUEST: "AID_REQUEST", 
        TAG_AID_RESPONSE: "AID_RESPONSE", 
        TAG_S1G_SECTOR_OPERATION: "S1G_SECTOR_OPERATION", 
        TAG_S1G_BEACON_COMPATIBILITY: "S1G_BEACON_COMPATIBILITY", 
        TAG_SHORT_BEACON_INTERVAL: "SHORT_BEACON_INTERVAL", 
        TAG_CHANGE_SEQUENCE: "CHANGE_SEQUENCE", 
        TAG_TWT: "TWT", 
        TAG_S1G_CAPABILITIES: "S1G_CAPABILITIES", 
        TAG_SUBCHANNEL_SELECTIVE_TRANSMISSION: "SUBCHANNEL_SELECTIVE_TRANSMISSION", 
   
   TAG_VENDOR_SPECIFIC_IE:                   "Vendor Specific" ,

        TAG_AUTHENTICATION_CONTROL: "AUTHENTICATION_CONTROL",
        TAG_TSF_TIMER_ACCURACY: "TSF_TIMER_ACCURACY",
        TAG_S1G_RELAY: "S1G_RELAY",
        TAG_REACHABLE_ADDRESS: "REACHABLE_ADDRESS",
        TAG_S1G_RELAY_DISCOVERY: "S1G_RELAY_DISCOVERY",
        TAG_AID_ANNOUNCEMENT: "AID_ANNOUNCEMENT",
        TAG_PV1_PROBE_RESPONSE_OPTION: "PV1_PROBE_RESPONSE_OPTION",
        TAG_EL_OPERATION: "EL_OPERATION",
        TAG_SECTORIZED_GROUP_ID_LIST: "SECTORIZED_GROUP_ID_LIST",
        TAG_S1G_OPERATION: "S1G_OPERATION",
        TAG_HEADER_COMPRESSION: "HEADER_COMPRESSION",
        TAG_SST_OPERATION: "SST_OPERATION",
        TAG_MAD: "MAD",
        TAG_S1G_RELAY_ACTIVATION: "S1G_RELAY_ACTIVATION",
        TAG_CAG_NUMBER: "CAG_NUMBER",
        TAG_AP_CSN: "AP_CSN",
        TAG_FILS_INDICATION: "FILS_INDICATION",
        TAG_DILS: "DILS",
        TAG_FRAGMENT: "FRAGMENT",
        TAG_RSN_EXTENSION: "RSN_EXTENSION"
}

# 802.11 2020 page: 946 Table: 9-92 
elt_id_ext_map = {
    0: "Reserved",
    1: "Association Delay Info",
    2: "FILS Request Parameters",
    3: "FILS Key Confirmation",
    4: "FILS Session",
    5: "FILS HLP Container",
    6: "FILS IP Address Assignment",
    7: "Key Delivery",
    8: "FILS Wrapped Data",
    9: "FTM Synchronization Information",
    10: "Extended Request",
    11: "Estimated Service Parameters Inbound",
    12: "FILS Public Key",
    13: "FILS Nonce",
    14: "Future Channel Guidance",
    15: "Service Hint",
    16: "Service Hash",
    17: "CDMG Capabilities",
    18: "Dynamic Bandwidth Control",
    19: "CDMG Extended Schedule",
    20: "SSW Report",
    21: "Cluster Probe",
    22: "Extended Cluster Report",
    23: "Cluster Switch Announcement",
    24: "Enhanced Beam Tracking",
    25: "SPSH Report",
    26: "Clustering Interference Assessment",
    27: "CMMG Capabilities",
    28: "CMMG Operation",
    29: "CMMG Operating Mode Notification",
    30: "CMMG Link Margin",
    31: "CMMG Link Adaptation Acknowledgment",
    32: "Reserved",
    33: "Password identifier",
    34: "GLK-GCR Parameter Set",
        # From the 802.11ax-2021 Table 9-92
        35: "HE Capabilities",
        36: "HE Operation",
        37: "UORA Parameter Set element",
        38: "MU EDCA Parameter Set",
        39: "Spatial Reuse Parameter Set element",
        # end of 802.11ax-2021
    40: "GAS Extension",
        # From the 802.11ax-2021 Table 9-92
        41: "NDP Feedback Report Parameter Set element",
        42: "BSS Color Change Announcement",
        43: "Quiet Time Period",
        # end of 802.11ax-2021
    44: "Vendor Specific Request Element",
        # From the 802.11ax-2021 Table 9-92
        45: "ESS Report",
        46: "OPS",
        47: "HE BSS Load",
        # end of 802.11ax-2021
    48: "Reserved",
    49: "Reserved",
    50: "Reserved",
    51: "Reserved",
    52: "Max Channel Switch Time",
    53: "Estimated Service Parameters Outbound",
    54: "Operating Channel Information (OCI) Element",
        # From the 802.11ax-2021 Table 9-92
        55: "Multiple BSSID Configuration",
        # end of 802.11ax-2021
    56: "Non-Inheritance",
        # From the 802.11ax-2021 Table 9-92
        57: "Known BSSID",
        58: "Short SSID List",
        59: "HE 6 GHz Band Capabilities",
        60: "UL MU Power Capabilities",
        # end of 802.11ax-2021
    61: "Reserved",
    62: "Reserved",
    63: "Reserved",
    64: "Reserved",
    65: "Reserved",
    66: "Reserved",
    67: "Reserved",
    68: "Reserved",
    69: "Reserved",
    70: "Reserved",
    71: "Reserved",
    72: "Reserved",
    73: "Reserved",
    74: "Reserved",
    75: "Reserved",
    76: "Reserved",
    77: "Reserved",
    78: "Reserved",
    79: "Reserved",
    80: "Reserved",
    81: "Reserved",
    82: "Reserved",
    83: "Reserved",
    84: "Reserved",
    85: "Reserved",
    86: "Reserved",
    87: "Reserved",
    88: "MSCS Descriptor element",
    89: "TCLAS Mask",
    90: "Supplemental Class 2 Capabilities",
    91: "OCT Source",
    92: "Rejected Groups",
    93: "Anti-Clogging Token Container",
    94: "Reserved" # 94-255 Reserved
}

def human_readable_elt(elt_id):
    result = None
    # Check if the element ID is a standard tag
    if elt_id < 255:
        result = elt_id_map.get(elt_id)
    # Check if the element ID is an extended tag
    else:
        result = "EXT: " + elt_id_ext_map.get(elt_id % 255)
        
    if result is None:
        print(f"Warning: Element ID {elt_id} is nonexistent")
        result = "Nonexistent"
        
    return result
