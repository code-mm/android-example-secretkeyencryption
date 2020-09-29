#include <jni.h>
#include <cstring>
#include <malloc.h>
#include <android/log.h>

#define TAG "CPP"
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)


const char *PACKAGE_NAME = "com.ms.app";
//(签名的md5值自己可以写方法获取,或者用签名工具直接获取，一般对接微信sdk的时候也会要应用签名的MD5值)
const char *SIGN_MD5 = "01A71DF4C48F96AAE1A9496B2F8D73FB";

//获取Application实例
jobject getApplication(JNIEnv *env) {
    jobject application = NULL;
    //这里是你的Application的类路径,混淆时注意不要混淆该类和该类获取实例的方法比如getInstance
    jclass baseapplication_clz = env->FindClass("com/ms/app/App");
    if (baseapplication_clz != NULL) {
        jmethodID currentApplication = env->GetStaticMethodID(
                baseapplication_clz, "getInstance",
                "()Lcom/ms/app/App;");
        if (currentApplication != NULL) {
            application = env->CallStaticObjectMethod(baseapplication_clz, currentApplication);
        }
        env->DeleteLocalRef(baseapplication_clz);
    }
    return application;
}


// 字节流转换为十六进制字符串
void Hex2Str(const char *sSrc, char *sDest, int nSrcLen) {
    int i;
    char szTmp[3];

    for (i = 0; i < nSrcLen; i++) {
        sprintf(szTmp, "%02X", (unsigned char) sSrc[i]);
        memcpy(&sDest[i * 2], szTmp, 2);
    }
    return;
}

//md5
jstring toMd5(JNIEnv *env, jbyteArray source) {
    // MessageDigest
    jclass classMessageDigest = env->FindClass("java/security/MessageDigest");
    // MessageDigest.getInstance()
    jmethodID midGetInstance = env->GetStaticMethodID(classMessageDigest, "getInstance",
                                                      "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    // MessageDigest object
    jobject objMessageDigest = env->CallStaticObjectMethod(classMessageDigest, midGetInstance,
                                                           env->NewStringUTF("md5"));

    jmethodID midUpdate = env->GetMethodID(classMessageDigest, "update", "([B)V");
    env->CallVoidMethod(objMessageDigest, midUpdate, source);

    // Digest
    jmethodID midDigest = env->GetMethodID(classMessageDigest, "digest", "()[B");
    jbyteArray objArraySign = (jbyteArray) env->CallObjectMethod(objMessageDigest, midDigest);

    jsize intArrayLength = env->GetArrayLength(objArraySign);


    jbyte *byte_array_elements = env->GetByteArrayElements(objArraySign, NULL);
    size_t length = (size_t) intArrayLength * 2 + 1;

    char *char_result = (char *) malloc(length);
    memset(char_result, 0, length);

    Hex2Str((const char *) byte_array_elements, char_result, intArrayLength);

    // 在末尾补\0
    *(char_result + intArrayLength * 2) = '\0';
    jstring stringResult = env->NewStringUTF(char_result);
    // release
    env->ReleaseByteArrayElements(objArraySign, byte_array_elements, JNI_ABORT);
    // 指针
    free(char_result);
    return stringResult;
}


bool isRight = false;

//获取应用签名的MD5值并判断是否与本应用的一致
jboolean getSignature(JNIEnv *env) {
    LOGD("getSignature isRight: %d", isRight ? 1 : 0);
    if (!isRight) {//避免每次都进行校验浪费资源，只要第一次校验通过后，后边就不在进行校验
        jobject context = getApplication(env);
        // 获得Context类
        jclass cls = env->FindClass("android/content/Context");
        // 得到getPackageManager方法的ID
        jmethodID mid = env->GetMethodID(cls, "getPackageManager",
                                         "()Landroid/content/pm/PackageManager;");

        // 获得应用包的管理器
        jobject pm = env->CallObjectMethod(context, mid);

        // 得到getPackageName方法的ID
        mid = env->GetMethodID(cls, "getPackageName", "()Ljava/lang/String;");
        // 获得当前应用包名
        jstring packageName = (jstring) env->CallObjectMethod(context, mid);
        const char *c_pack_name = env->GetStringUTFChars(packageName, NULL);

        // 比较包名,若不一致，直接return包名
        if (strcmp(c_pack_name, PACKAGE_NAME) != 0) {
            return false;
        }
        // 获得PackageManager类
        cls = env->GetObjectClass(pm);
        // 得到getPackageInfo方法的ID
        mid = env->GetMethodID(cls, "getPackageInfo",
                               "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
        // 获得应用包的信息
        jobject packageInfo = env->CallObjectMethod(pm, mid, packageName,
                                                    0x40); //GET_SIGNATURES = 64;
        // 获得PackageInfo 类
        cls = env->GetObjectClass(packageInfo);
        // 获得签名数组属性的ID
        jfieldID fid = env->GetFieldID(cls, "signatures", "[Landroid/content/pm/Signature;");
        // 得到签名数组
        jobjectArray signatures = (jobjectArray) env->GetObjectField(packageInfo, fid);
        // 得到签名
        jobject signature = env->GetObjectArrayElement(signatures, 0);

        // 获得Signature类
        cls = env->GetObjectClass(signature);
        mid = env->GetMethodID(cls, "toByteArray", "()[B");
        // 当前应用签名信息
        jbyteArray signatureByteArray = (jbyteArray) env->CallObjectMethod(signature, mid);
        //转成jstring
        jstring str = toMd5(env, signatureByteArray);
        char *c_msg = (char *) env->GetStringUTFChars(str, 0);
        LOGD("getSignature release sign md5: %s", c_msg);
        isRight = strcmp(c_msg, SIGN_MD5) == 0;
        return isRight;
    }
    return isRight;
}


extern "C" JNIEXPORT void JNICALL
Java_com_ms_app_MainActivity_test(JNIEnv *env, jobject cls) {
    //加密算法各有不同，这里我就用md5做个示范
    int res = getSignature(env);

    if (res) {
        LOGE("验证通过 ");
    } else {
        LOGE("验证未通过 ");
    }
}

