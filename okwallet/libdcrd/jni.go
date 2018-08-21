package main

/*
// free()
#include <stdlib.h>

#include <jni.h>

static const jchar* _GoJniGetStringChars(JNIEnv *env, jstring str, jboolean* isCopy)
{
  return (*env)->GetStringChars(env, str, isCopy);
}

static jsize _GoJniGetStringLength(JNIEnv* env, jstring str)
{
  return (*env)->GetStringLength(env, str);
}

static jobjectArray _GoJniNewObjectArray(JNIEnv* env, jsize len, jclass cls, jobject init)
{
  return (*env)->NewObjectArray(env, len, cls, init);
}

static jstring _GoJniNewString(JNIEnv *env, const jchar* unicode, jsize len)
{
  return (*env)->NewString(env, unicode, len);
}

static void _GoJniReleaseStringChars(JNIEnv *env, jstring str, const jchar* chars)
{
  return (*env)->ReleaseStringChars(env, str, chars);
}

static void _GoJniSetObjectArrayElement(JNIEnv *env, jobjectArray array, jsize index, jobject v)
{
  return (*env)->SetObjectArrayElement(env, array, index, v);
}

static jobject _GoJniGetObjectArrayElement(JNIEnv* env, jobjectArray array, jsize index)
{
  return (*env)->GetObjectArrayElement(env, array, index);
}

static jclass _GoJniFindClass(JNIEnv *env, const char* name)
{
  return (*env)->FindClass(env, name);
}
*/
import "C"

import (
	"errors"
	"reflect"
	"unicode/utf16"
	"unsafe"
)

func string2jstring(env *C.JNIEnv, s string) C.jstring {
	runes := []rune(s)
	unicode := utf16.Encode(runes)

	header := (*reflect.SliceHeader)(unsafe.Pointer(&unicode))
	c_unicode := (*C.jchar)(unsafe.Pointer(header.Data))
	c_len := C.jsize(header.Len)

	return C._GoJniNewString(env, c_unicode, c_len)
}

func jstring2string(env *C.JNIEnv, js C.jstring) (string, error) {
	chars, _, err := getStringChars(env, js)
	if err != nil {
		return "", err
	}
	defer releaseStringChars(env, js, chars)

	runes := utf16.Decode(chars)
	result := string(runes)

	return result, nil
}

func getStringChars(env *C.JNIEnv, js C.jstring) (chars []uint16, isCopy bool, err error) {
	var c_isCopy C.jboolean

	_len := getJStringLength(env, js)
	c_chars := getJStringChars(env, js, &c_isCopy)

	header := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(c_chars)),
		Len:  _len,
		Cap:  _len,
	}
	chars = *(*[]uint16)(unsafe.Pointer(&header))
	if chars == nil {
		err = errors.New("The operation failed")
		return
	}

	isCopy = jbool2bool(c_isCopy)
	err = nil
	return
}

func getJStringLength(env *C.JNIEnv, js C.jstring) int {
	return int(C.jint(C._GoJniGetStringLength(env, js)))
}

func getJStringChars(env *C.JNIEnv, js C.jstring, isCopy *C.jboolean) *C.jchar {
	return C._GoJniGetStringChars(env, js, isCopy)
}

func releaseStringChars(env *C.JNIEnv, js C.jstring, chars []uint16) {
	header := (*reflect.SliceHeader)(unsafe.Pointer(&chars))
	c_chars := (*C.jchar)(unsafe.Pointer(header.Data))

	header.Data = uintptr(0)
	header.Len = 0
	header.Cap = 0

	C._GoJniReleaseStringChars(env, js, c_chars)
}

func newObjectArray(env *C.JNIEnv, cls C.jclass, _len int, init C.jobject) C.jobjectArray {
	return C._GoJniNewObjectArray(env, int2jsize(_len), cls, init)
}

func newStringObjectArray(env *C.JNIEnv, _len int) C.jobjectArray {
	var init C.jobject
	return C._GoJniNewObjectArray(env, int2jsize(_len), findClass(env, "java/lang/String"), init)
}

func setObjectArrayStringElement(env *C.JNIEnv, array C.jobjectArray, index int, s string) {
	C._GoJniSetObjectArrayElement(env, array, int2jsize(index), C.jobject(string2jstring(env, s)))
}

func int2jsize(n int) C.jsize {
	return C.jsize(uint(n))
}

func jbool2bool(jb C.jboolean) bool {
	return jb == C.JNI_TRUE
}

func findClass(env *C.JNIEnv, name string) C.jclass {
	pc := C.CString(name)
	defer C.free(unsafe.Pointer(pc))

	return C._GoJniFindClass(env, pc)
}
