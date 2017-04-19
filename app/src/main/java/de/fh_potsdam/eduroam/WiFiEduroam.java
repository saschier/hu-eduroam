/* Copyright 2013 Wilco Baan Hofman <wilco@baanhofman.nl>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package de.fh_potsdam.eduroam;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import android.content.Context;
import android.security.KeyChain;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.AlertDialog.Builder;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiEnterpriseConfig.Phase2;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

// API level 18 and up
import android.net.wifi.WifiEnterpriseConfig;
import android.net.wifi.WifiEnterpriseConfig.Eap;


public class WiFiEduroam extends Activity {
  private static final String INT_EAP = "eap";
  private static final String INT_EAP_PHASE2 = "phase2";
  private static final String INT_CA_CERT = "ca_cert";
  private static final String INT_SUBJECT_MATCH = "subject_match";
  private static final String INT_ANONYMOUS_IDENTITY = "anonymous_identity";
  private static final String INT_IDENTITY = "identity";
  private static final String INT_PASSWORD = "password";
  private static final String INT_ENTERPRISEFIELD_NAME = "android.net.wifi.WifiConfiguration$EnterpriseField";
  // Because android.security.Credentials cannot be resolved...
  private static final String INT_KEYSTORE_URI = "keystore://";
  private static final String INT_CA_PREFIX = INT_KEYSTORE_URI + "CACERT_";
  protected static AlertDialog alertDialog;
  private Handler mHandler = new Handler();
  private EditText username;
  private EditText password;
  private String ca;
  private String ca_name = "tcom";
  private String subject_match = "dc1.campus.fh-potsdam.de";
  private String realm = "@fh-potsdam.de";
  private String ssid = "eduroam";
  private List<String> ssids2remove = Arrays.asList("eduroam","FH-Potsdam","FHP-Guest");
  private boolean busy = false;
  private Toast toast = null;
  
  static String removeQuotes(String str) {
    int len = str.length();
    if ((len > 1) && (str.charAt(0) == '"') && (str.charAt(len - 1) == '"')) {
      return str.substring(1, len - 1);
    }
    return str;
  }

  static String surroundWithQuotes(String string) {
    return "\"" + string + "\"";
  }

  // read file into string
  // source: http://stackoverflow.com/a/5445161
  static String convertStreamToString(java.io.InputStream is) {
    java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
    return s.hasNext() ? s.next() : "";
}

  // Called when the activity is first created.
  @Override
  public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.logon);

    username = (EditText) findViewById(R.id.username);
    password = (EditText) findViewById(R.id.password);

    alertDialog = new AlertDialog.Builder(this).create();

    Button myButton = (Button) findViewById(R.id.button1);
    if (myButton == null)
      throw new RuntimeException("button1 not found. Odd");


    myButton.setOnClickListener(new Button.OnClickListener() {
      public void onClick(View _v) {
        if (busy) {
          return;
        }
        busy = true;
        // Most of this stuff runs in the background
        Thread t = new Thread() {
          @Override
          public void run() {
            try {
              updateStatus("Installing WiFi profile...");
              InputStream caCertInputStream = getResources().openRawResource(R.raw.deutsche_telekom_root_ca_2);
              ca = convertStreamToString(caCertInputStream);
              if (android.os.Build.VERSION.SDK_INT >= 14 && android.os.Build.VERSION.SDK_INT <= 17) {
                // 11 == 3.0 Honeycomb 02/2011, 17 == 4.2 Jelly Bean
                installCertificates();
              } else if (android.os.Build.VERSION.SDK_INT >= 18) {
                // new features since 4.3
                saveWifiConfig();
                updateStatus("All done!");
                // Clear the password field in the UI thread
                mHandler.post(new Runnable() {
                  @Override
                  public void run() {
                    password.setText("");
                  }
                });

              } else {
                throw new RuntimeException("What version is this?! API Mismatch");
              }
            } catch (RuntimeException e) {
              updateStatus("Runtime Error: " + e.getMessage());
              e.printStackTrace();
            } catch (Exception e) {
              e.printStackTrace();
            }
            busy = false;
          }
        };
        t.start();

      }
    });

  }

  private boolean saveWifiConfig() {
    //WifiManager wifiManager = (WifiManager) this.getSystemService(WIFI_SERVICE);
    WifiManager wifiManager = (WifiManager) this.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
    wifiManager.setWifiEnabled(true);

    WifiConfiguration currentConfig = new WifiConfiguration();

    List<WifiConfiguration> configs = null;
    // try to get the configured networks for 10 seconds
    for (int i = 0; i < 10 && configs == null; i++) {
      configs = wifiManager.getConfiguredNetworks();
      try {
        Thread.sleep(1);
      }
      catch(InterruptedException e) {
        continue;
      }
    }

    // Remove existing eduroam profiles
    // There could possibly be more than one "eduroam" profile, which could cause errors
    // We don't know which wrong settings existing profiles contain, just remove them
    if (configs != null) {
      for (WifiConfiguration config : configs) {
        for (String ssid : ssids2remove) {
          if (config.SSID.equals(surroundWithQuotes(ssid))) {
            if (BuildConfig.DEBUG) { System.out.println(config.toString()); }
            wifiManager.removeNetwork(config.networkId);
          }
        }
      }
    }

    currentConfig.SSID = ssid;
    currentConfig.hiddenSSID = false;
    currentConfig.priority = 999;
    currentConfig.status = WifiConfiguration.Status.DISABLED;

    currentConfig.allowedKeyManagement.clear();
    currentConfig.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_EAP);

    // GroupCiphers (Allow only secure ciphers)
    currentConfig.allowedGroupCiphers.clear();
    currentConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);


    // PairwiseCiphers (CCMP = WPA2 only)
    currentConfig.allowedPairwiseCiphers.clear();
    currentConfig.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);

    // Authentication Algorithms (OPEN)
    currentConfig.allowedAuthAlgorithms.clear();
    currentConfig.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);

    // Protocols (RSN/WPA2 only)
    currentConfig.allowedProtocols.clear();
    currentConfig.allowedProtocols.set(WifiConfiguration.Protocol.RSN);

    String identity;
    if(username.getText().toString().endsWith(realm)) identity =  username.getText().toString();
    else identity = username.getText().toString() + realm;

    // Enterprise Settings
    HashMap<String,String> configMap = new HashMap<String,String>();
    configMap.put(INT_SUBJECT_MATCH, subject_match);
    configMap.put(INT_ANONYMOUS_IDENTITY, "anonymous" + realm);
    configMap.put(INT_IDENTITY,  identity);
    configMap.put(INT_PASSWORD,  password.getText().toString());
    configMap.put(INT_EAP, "PEAP");
    configMap.put(INT_EAP_PHASE2, "3");
    configMap.put(INT_CA_CERT, INT_CA_PREFIX + ca_name);

    if (android.os.Build.VERSION.SDK_INT >= 14 && android.os.Build.VERSION.SDK_INT <= 17) {
      applyAndroid4_42EnterpriseSettings(currentConfig, configMap);
    } else if (android.os.Build.VERSION.SDK_INT >= 18) {
      applyAndroid43EnterpriseSettings(currentConfig, configMap);
    } else {
      throw new RuntimeException("API version mismatch!");
    }

    // add our new network
    int res = wifiManager.addNetwork(currentConfig);
    boolean enabled = false;
    if (res<0) {
      System.out.println("Adding profile failed. "+ res);
    }
    else {
      System.out.println("Adding profile success: "+ res);
      boolean c = wifiManager.saveConfiguration();
      System.out.println("Save Configuration: " + c);
      enabled = wifiManager.enableNetwork(res, true);
      System.out.println("WiFi enabled: "+enabled);
    }
    return enabled;
  }

  @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
  private void applyAndroid43EnterpriseSettings(WifiConfiguration currentConfig, HashMap<String,String> configMap) {
    try {
      CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
      InputStream in = new ByteArrayInputStream(Base64.decode(ca.replaceAll("-----(BEGIN|END) CERTIFICATE-----", "")));
      X509Certificate caCert = (X509Certificate) certFactory.generateCertificate(in);

      WifiEnterpriseConfig enterpriseConfig = new WifiEnterpriseConfig();
      enterpriseConfig.setPhase2Method(Phase2.MSCHAPV2);
      enterpriseConfig.setAnonymousIdentity(configMap.get(INT_ANONYMOUS_IDENTITY));
      enterpriseConfig.setEapMethod(Eap.PEAP);

      enterpriseConfig.setCaCertificate(caCert);
      enterpriseConfig.setIdentity(configMap.get(INT_IDENTITY));
      if (android.os.Build.VERSION.SDK_INT < 23) {
        enterpriseConfig.setSubjectMatch(configMap.get(INT_SUBJECT_MATCH));
      } else {
        enterpriseConfig.setAltSubjectMatch(configMap.get("DNS:" + INT_SUBJECT_MATCH));
      }
      currentConfig.enterpriseConfig = enterpriseConfig;

    } catch(Exception e) {
      e.printStackTrace();
    }
  }
  
  @TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
  // Step 1 for android 4.0 - 4.2
  private void installCertificates() {
    // Install the CA certificate
    updateStatus("Inputting CA certificate.");
    Intent intent = KeyChain.createInstallIntent();
    intent.putExtra(KeyChain.EXTRA_NAME, ca_name);
    intent.putExtra(KeyChain.EXTRA_CERTIFICATE, Base64.decode(ca.replaceAll("-----(BEGIN|END) CERTIFICATE-----", "")));
    startActivityForResult(intent, 3);
  }
  
  @Override
  @TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
  // Step 2 for android 4.0 - 4.2; dispatcher for later steps
  public void onActivityResult(int requestCode, int resultCode, Intent intent) {
    if (resultCode != RESULT_OK) {
      updateStatus("Aborted.");
      return;
    }
    if (requestCode == 1) {
      alert("Password", "In the next dialog, type \"" + ssid + "\" as the password.");
      return;
    }
    if (requestCode == 3) {
      saveWifiConfig();
      updateStatus("All done!");
      password.setText("");
      return;
    }
  }

  @TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
  // Last step for android 4.0 - 4.2, called from saveWifiConfig
  private void applyAndroid4_42EnterpriseSettings(WifiConfiguration currentConfig, HashMap<String,String> configMap){
    // NOTE: This code is mighty ugly, but reflection is the only way to get the methods we need
    // Get the enterprise class via reflection
    Class<?>[] wcClasses = WifiConfiguration.class.getClasses();
    Class<?> wcEnterpriseField = null;

    for (Class<?> wcClass : wcClasses) {
      if (wcClass.getName().equals(INT_ENTERPRISEFIELD_NAME)) {
        wcEnterpriseField = wcClass;
        break;
      }
    }
    if (wcEnterpriseField == null) {
      throw new RuntimeException("There is no enterprisefield class.");
    }

    // Get the setValue handler via reflection
    Method wcefSetValue = null;
    for (Method m: wcEnterpriseField.getMethods()) {
      if(m.getName().equals("setValue")) {
        wcefSetValue = m;
        break;
      }
    }
    if(wcefSetValue == null) {
      throw new RuntimeException("There is no setValue method.");
    }

    // Fill fields from the HashMap
    Field[] wcefFields = WifiConfiguration.class.getFields();
    for (Field wcefField : wcefFields) {
      if (configMap.containsKey(wcefField.getName())) {
        try {
          wcefSetValue.invoke(wcefField.get(currentConfig),
              configMap.get(wcefField.getName()));
        } catch (Exception e) {
          e.printStackTrace();
        }
      }
    }
  }
  
  @Override
  public boolean onCreateOptionsMenu(Menu menu) {
    MenuInflater inflater = getMenuInflater();
    inflater.inflate(R.menu.options_menu, menu);
    return true;
  }
    
  @Override
  public boolean onOptionsItemSelected(MenuItem item){
    Builder builder = new AlertDialog.Builder(this);
    switch (item.getItemId()) {
      case R.id.about:
        PackageInfo pi = null;
        try{
          pi = getPackageManager().getPackageInfo(getClass().getPackage().getName(), 0);
        } catch(Exception e){
          e.printStackTrace();
        }
        builder.setTitle(getString(R.string.ABOUT_TITLE));
        builder.setMessage(getString(R.string.ABOUT_CONTENT)+
          "\n\n"+pi.packageName+"\n"+
          "V"+pi.versionName+
          "C"+pi.versionCode);
      builder.setPositiveButton(getString(android.R.string.ok), null);
      builder.show();

          return true;
      case R.id.exit:
        System.exit(0);
      }
      return false;
  }

  /* Update the status in the main thread */
  protected void updateStatus(final String text) {
    mHandler.post(new Runnable() {
      @Override
      public void run() {
        System.out.println(text);
        if (toast != null)
          toast.cancel();
        toast = Toast.makeText(getBaseContext(), text, Toast.LENGTH_LONG);
        toast.show();
      }
    });
  }

  private void alert(String title, String message) {
    AlertDialog alertBox = new AlertDialog.Builder(this).create();
    alertBox.setTitle(title);
    alertBox.setMessage(message);
    alertBox.setButton(AlertDialog.BUTTON_POSITIVE, "OK", new DialogInterface.OnClickListener(){

      @Override
      public void onClick(DialogInterface dialog, int which) {
        onActivityResult(2, RESULT_OK, null);
      }
    });
    alertBox.show();
  }
}
