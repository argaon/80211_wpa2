#ifndef WLAN_KEY_VALUE_H
#define WLAN_KEY_VALUE_H
#pragma pack(push,1)
/********************Beacon info Key & value*******************/
struct beacon_info_key{
    u_int8_t bssid[6];
};
struct beacon_info_value{
    int beacon_count;
    int data;
    int ch;
    u_int8_t ESSID[];
};
struct bssid_station_key{
    u_int8_t bssid[6];
};
struct bssid_station_value{
    u_int8_t station[6];
    int frames;
};
#pragma pack(pop)
#endif // WLAN_KEY_VALUE_H

