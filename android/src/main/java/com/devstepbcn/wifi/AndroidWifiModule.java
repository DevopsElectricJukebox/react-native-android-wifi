package com.devstepbcn.wifi;

import com.facebook.react.uimanager.*;
import com.facebook.react.bridge.*;
import com.facebook.systrace.Systrace;
import com.facebook.systrace.SystraceMessage;
// import com.facebook.react.LifecycleState;
import com.facebook.react.ReactInstanceManager;
import com.facebook.react.ReactRootView;
import com.facebook.react.modules.core.DefaultHardwareBackBtnHandler;
import com.facebook.react.modules.core.DeviceEventManagerModule;
import com.facebook.react.shell.MainReactPackage;
import com.facebook.soloader.SoLoader;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableNativeArray;
import com.facebook.react.bridge.WritableNativeMap;

import android.provider.Settings;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiConfiguration;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.net.NetworkCapabilities;
import android.net.Network;
import android.net.Uri;
import android.net.wifi.WifiInfo;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.BroadcastReceiver;
import android.os.Build;
import android.os.Bundle;
import android.widget.Toast;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.lang.Thread;
import java.util.Map;

class WifiNetworkObject extends HashMap<String, Object> {};

public class AndroidWifiModule extends ReactContextBaseJavaModule {

	//WifiManager Instance
	WifiManager wifi;
	ReactApplicationContext context;
	HashMap<String, WifiNetworkObject> rememberedNetworks;

	//Constructor
	public AndroidWifiModule(ReactApplicationContext reactContext) {
		super(reactContext);
		wifi = (WifiManager)reactContext.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
		context = (ReactApplicationContext) getReactApplicationContext();
		rememberedNetworks = new HashMap<String, WifiNetworkObject>();
	}

	//Name for module register to use:
	@Override
	public String getName() {
		return "AndroidWifiModule";
	}

	private WifiNetworkObject networkObjectFromScanResult(ScanResult result) {
		WifiNetworkObject wifiObject = new WifiNetworkObject();
		wifiObject.put("SSID", result.SSID);
		wifiObject.put("BSSID", result.BSSID);
		wifiObject.put("capabilities", result.capabilities);
		wifiObject.put("frequency", result.frequency);
		wifiObject.put("levelDb", result.level);
		wifiObject.put("timestamp", result.timestamp);
		return wifiObject;
	}

	//Method to load wifi list into string via Callback.
	@ReactMethod
	public void loadWifiList(Promise promise) {
		List<ScanResult> results = wifi.getScanResults();
		WritableNativeArray wifiArray = new WritableNativeArray();
		for (ScanResult result: results) {
			if(!result.SSID.equals("")){
				WifiNetworkObject object = networkObjectFromScanResult(result);
				wifiArray.pushMap(Arguments.makeNativeMap(object));
				this.rememberedNetworks.put(result.BSSID, object);
			}
		}
		promise.resolve(wifiArray);
	}

	//Method to force wifi usage if the user needs to send requests via wifi
	//if it does not have internet connection. Useful for IoT applications, when
	//the app needs to communicate and send requests to a device that have no 
	//internet connection via wifi.

	//Receives a boolean to enable forceWifiUsage if true, and disable if false.
	//Is important to enable only when communicating with the device via wifi 
	//and remember to disable it when disconnecting from device.
	@ReactMethod
	public void forceWifiUsage(boolean useWifi) {
        boolean canWriteFlag = false;
		
        if (useWifi) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    canWriteFlag = Settings.System.canWrite(context);

                    if (!canWriteFlag) {
                        Intent intent = new Intent(Settings.ACTION_MANAGE_WRITE_SETTINGS);
                        intent.setData(Uri.parse("package:" + context.getPackageName()));
                        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

                        context.startActivity(intent);
                    }

                }


                if (((Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) && canWriteFlag) || ((Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) && !(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M))) {
                    final ConnectivityManager manager = (ConnectivityManager) context
                            .getSystemService(Context.CONNECTIVITY_SERVICE);
                    NetworkRequest.Builder builder;
                    builder = new NetworkRequest.Builder();
                    //set the transport type do WIFI
                    builder.addTransportType(NetworkCapabilities.TRANSPORT_WIFI);


                    manager.requestNetwork(builder.build(), new ConnectivityManager.NetworkCallback() {
                        @Override
                        public void onAvailable(Network network) {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                manager.bindProcessToNetwork(network);
                            } else {
                                //This method was deprecated in API level 23
                                ConnectivityManager.setProcessDefaultNetwork(network);
                            }
                            try {
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                            manager.unregisterNetworkCallback(this);
                        }
                    });
                }


            }
        } else {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                ConnectivityManager manager = (ConnectivityManager) context
                        .getSystemService(Context.CONNECTIVITY_SERVICE);
                manager.bindProcessToNetwork(null);
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                ConnectivityManager.setProcessDefaultNetwork(null);
            }
        }
    }

	//Method to check if wifi is enabled
	@ReactMethod
	public void isEnabled(Callback isEnabled) {
		isEnabled.invoke(wifi.isWifiEnabled());
	}

	//Method to connect/disconnect wifi service
	@ReactMethod
	public void setEnabled(Boolean enabled) {
		wifi.setWifiEnabled(enabled);
	}

	//Send the ssid and password of a Wifi network into this to connect to the network.
	//Example:  wifi.findAndConnect(ssid, password);
	//After 10 seconds, a post telling you whether you are connected will pop up.
	//Callback returns true if ssid is in the range
	// @ReactMethod
	// public void findAndConnect(String ssid, String password, Callback ssidFound) {
	// 	List < ScanResult > results = wifi.getScanResults();
	// 	int connected = -1;
	// 	for (ScanResult result: results) {
	// 		String resultString = "" + result.SSID;
	// 		if (ssid.equals(resultString)) {
	// 			connected = connectTo(result.capabilities, password, ssid, result.BSSID);
	// 		}
	// 	}
	// 	ssidFound.invoke(connected);
	// }

	//Use this method to check if the device is currently connected to Wifi.
	@ReactMethod
	public void connectionStatus(Callback connectionStatusResult) {
		ConnectivityManager connManager = (ConnectivityManager) getReactApplicationContext().getSystemService(Context.CONNECTIVITY_SERVICE);
		NetworkInfo mWifi = connManager.getNetworkInfo(ConnectivityManager.TYPE_WIFI);
		if (mWifi.isConnected()) {
			connectionStatusResult.invoke(true);
		} else {
			connectionStatusResult.invoke(false);
		}
	}

	@ReactMethod
	public void connectTo(String capabilities, String password, String ssid, String bssid, Promise connected) {
		int isConnected = connectTo(capabilities, password, ssid, bssid);
		if (isConnected == 0) {
			connected.resolve(true);
		} else {
			connected.reject("CONNECTION_ERROR", "Connection error. Code: " + Integer.toString(isConnected));
		}
	}

	//Method to connect to WIFI Network
	public Integer connectTo(String capabilities, String password, String ssid, String bssid) {
		//Make new configuration
		WifiConfiguration conf = new WifiConfiguration();
		
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
        conf.SSID = ssid;
    } else {
        conf.SSID = "\"" + ssid + "\"";
		}
		conf.BSSID = bssid;
		
		if (capabilities.contains("WPA")  || 
          capabilities.contains("WPA2") || 
          capabilities.contains("WPA/WPA2 PSK")) {

	    // appropriate ciper is need to set according to security type used,
	    // ifcase of not added it will not be able to connect
			if (password != null) {
				conf.preSharedKey = "\"" + password + "\"";
			}
	    
	    conf.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
	    
	    conf.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);
	    
	    conf.status = WifiConfiguration.Status.ENABLED;
	    
	    conf.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
	    conf.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
	    
	    conf.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);
	    
	    conf.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
	    conf.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
	    
	    conf.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
	    conf.allowedProtocols.set(WifiConfiguration.Protocol.WPA);

		}	else if (capabilities.contains("WEP")) {
			conf.wepKeys[0] = "\"" + password + "\"";
			conf.wepTxKeyIndex = 0;
			conf.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
			conf.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP40);

		} else {
			conf.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
		}

		//Remove the existing configuration for this netwrok
		List<WifiConfiguration> mWifiConfigList = wifi.getConfiguredNetworks();

		int updateNetwork = -1;

		for(WifiConfiguration wifiConfig : mWifiConfigList){
			if(wifiConfig.SSID.equals(conf.SSID)){
				conf.networkId = wifiConfig.networkId;
				updateNetwork = wifi.updateNetwork(conf);
			}
		}

    // If network not already in configured networks add new network
		if ( updateNetwork == -1 ) {
      updateNetwork = wifi.addNetwork(conf);
      wifi.saveConfiguration();
		};

    if ( updateNetwork == -1 ) {
      return -1;
    }

    boolean disconnect = wifi.disconnect();
		if ( !disconnect ) {
			return -2;
		};

		boolean enableNetwork = wifi.enableNetwork(updateNetwork, true);
		if ( !enableNetwork ) {
			return -3;
		};

		return 0;
	}

	//Disconnect current Wifi.
	@ReactMethod
	public void disconnect() {
		wifi.disconnect();
	}

	//This method will return current ssid
	@ReactMethod
	public void getSSID(final Promise promise) {
		WifiInfo info = wifi.getConnectionInfo();

		// This value should be wrapped in double quotes, so we need to unwrap it.
		String ssid = info.getSSID();
		if(ssid == null  || ssid.equals("0x")|| ssid.equals("<unknown ssid>")) {
			ssid = null;
		} else {
			if (ssid.startsWith("\"") && ssid.endsWith("\"")) {
				ssid = ssid.substring(1, ssid.length() - 1);
			}
		}

		promise.resolve(ssid);
	}

	//This method will return the basic service set identifier (BSSID) of the current access point
	@ReactMethod
	public void getBSSID(final Callback callback) {
		WifiInfo info = wifi.getConnectionInfo();

		String bssid = info.getBSSID();

		callback.invoke(bssid.toUpperCase());
	}

	//This method will return current wifi signal strength
	@ReactMethod
	public void getCurrentSignalStrength(final Callback callback) {
		int linkSpeed = wifi.getConnectionInfo().getRssi();
		callback.invoke(linkSpeed);
	}

	//This method will return current wifi frequency
	@ReactMethod
	public void getFrequency(final Callback callback) {
		WifiInfo info = wifi.getConnectionInfo();
		int frequency = info.getFrequency();
		callback.invoke(frequency);
	}

	//This method will return current IP
	@ReactMethod
	public void getIP(final Callback callback) {
		WifiInfo info = wifi.getConnectionInfo();
		String stringip = longToIP(info.getIpAddress());
		callback.invoke(stringip);
	}

	//This method will remove the wifi network as per the passed SSID from the device list
	@ReactMethod
	public void removeWifiNetwork(String ssid, final Promise promise) {
    List<WifiConfiguration> mWifiConfigList = wifi.getConfiguredNetworks();
    for (WifiConfiguration wifiConfig : mWifiConfigList) {
				String comparableSSID = ('"' + ssid + '"'); //Add quotes because wifiConfig.SSID has them
				if(wifiConfig.SSID.equals(comparableSSID)) {
					wifi.removeNetwork(wifiConfig.networkId);
					wifi.saveConfiguration();
				}
    }
		promise.resolve(true);
	}

	// This method is similar to `loadWifiList` but it forcefully starts the wifi scanning on android and in the callback fetches the list
	@ReactMethod
	public void rescanAndLoadWifiList(Promise promise) {
		WifiReceiver receiverWifi = new WifiReceiver(wifi, promise, this.rememberedNetworks);
   	getReactApplicationContext().getCurrentActivity().registerReceiver(receiverWifi, new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION));
    wifi.startScan();
	}

	@ReactMethod
	public void getKnownNetworks(Promise promise) {
		WritableNativeMap wifiObject = new WritableNativeMap();
		for (HashMap.Entry<String, WifiNetworkObject> network : this.rememberedNetworks.entrySet()) {
			wifiObject.putMap(network.getKey(), Arguments.makeNativeMap(network.getValue()));
		}
		promise.resolve(wifiObject);
	}

	@ReactMethod
	public void getConfiguredNetworks(Promise promise) {
		List<WifiConfiguration> mWifiConfigList = wifi.getConfiguredNetworks();
		WritableNativeArray wifiArray = new WritableNativeArray();
		for (WifiConfiguration wifiConfig : mWifiConfigList) {
			WritableNativeMap wifiObject = new WritableNativeMap();
			if (!wifiConfig.SSID.equals("")){
				String ssid = wifiConfig.SSID;
				if (ssid.startsWith("\"") && ssid.endsWith("\"")) {
					ssid = ssid.substring(1, ssid.length() - 1);
				}
				wifiObject.putString("ssid", ssid);
				wifiObject.putString("bssid", wifiConfig.BSSID);

				if (wifiConfig.allowedProtocols.get(WifiConfiguration.Protocol.RSN)) {
					wifiObject.putString("capabilities", "WPA2");
				} else if (wifiConfig.allowedKeyManagement.get(WifiConfiguration.KeyMgmt.WPA_PSK)) {
					wifiObject.putString("capabilities", "WPA");
				} else if (wifiConfig.allowedKeyManagement.get(WifiConfiguration.KeyMgmt.WPA_EAP) || wifiConfig.allowedKeyManagement.get(WifiConfiguration.KeyMgmt.IEEE8021X)) {
					wifiObject.putString("capabilities", "EAP");
				} else if (wifiConfig.allowedGroupCiphers.get(WifiConfiguration.GroupCipher.WEP40)) {
					wifiObject.putString("capabilities", "WEP");
				} else {
					wifiObject.putString("capabilities", "");
				}

				wifiArray.pushMap(wifiObject);
			}
		}
		promise.resolve(wifiArray);
	}

	@ReactMethod
	public void getCurrentNetworkInfo(final Promise promise) {
		try {
			WifiInfo wifiInfo = wifi.getConnectionInfo();
			if (wifiInfo != null) {
				WritableNativeMap wifiInfoObject = new WritableNativeMap();
				String ssid = wifiInfo.getSSID();
				if (ssid.startsWith("\"") && ssid.endsWith("\"")) {
					ssid = ssid.substring(1, ssid.length() - 1);
				}

				wifiInfoObject.putString("bssid", wifiInfo.getBSSID());
				wifiInfoObject.putString("ssid", ssid);
				wifiInfoObject.putString("macAddress", wifiInfo.getMacAddress());
				wifiInfoObject.putString("ipAddress", longToIP(wifiInfo.getIpAddress()));
				wifiInfoObject.putInt("rssi", wifiInfo.getRssi());
				wifiInfoObject.putInt("linkSpeed", wifiInfo.getLinkSpeed());
				
				promise.resolve(wifiInfoObject);
			} else {
				promise.resolve(null);
			}
		} catch (Exception e) {
			promise.reject("Error", e);
		}
	}

	public static String longToIP(int longIp){
		StringBuffer sb = new StringBuffer("");
		String[] strip=new String[4];
		strip[3]=String.valueOf((longIp >>> 24));
		strip[2]=String.valueOf((longIp & 0x00FFFFFF) >>> 16);
		strip[1]=String.valueOf((longIp & 0x0000FFFF) >>> 8);
		strip[0]=String.valueOf((longIp & 0x000000FF));
		sb.append(strip[0]);
		sb.append(".");
		sb.append(strip[1]);
		sb.append(".");
		sb.append(strip[2]);
		sb.append(".");
		sb.append(strip[3]);
		return sb.toString();
	}

	class WifiReceiver extends BroadcastReceiver {

			// private Callback successCallback;
			// private Callback errorCallback;
			private WifiManager wifi;
			private Promise promise;
			private HashMap<String, WifiNetworkObject> rememberedNetworks;

			public WifiReceiver(final WifiManager wifi, Promise promise, HashMap<String, WifiNetworkObject> rememberedNetworks) {
				super();
				// this.successCallback = successCallback;
				// this.errorCallback = errorCallback;
				this.wifi = wifi;
				this.promise = promise;
				this.rememberedNetworks = rememberedNetworks;
 			}

			// This method call when number of wifi connections changed
      		public void onReceive(Context c, Intent intent) {
				// LocalBroadcastManager.getInstance(c).unregisterReceiver(this);
				c.unregisterReceiver(this);
				// getReactApplicationContext().getCurrentActivity().registerReceiver
				try {
					List < ScanResult > results = this.wifi.getScanResults();
					WritableNativeArray wifiArray = new WritableNativeArray();

					for (ScanResult result : results) {
						if (!result.SSID.equals("")){
							WifiNetworkObject wifiObject = networkObjectFromScanResult(result);
							this.rememberedNetworks.put(result.BSSID, wifiObject);
							wifiArray.pushMap(Arguments.makeNativeMap(wifiObject));
						}
					}
					this.promise.resolve(wifiArray);
					return;
				} catch (IllegalViewOperationException e) {
					this.promise.reject("ILLEGAL_VIEW_OPERATION", e.getMessage());
					return;
				}
      }
  }
}
