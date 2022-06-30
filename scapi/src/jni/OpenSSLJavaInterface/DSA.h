/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/

/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA */

#ifndef _Included_edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA
#define _Included_edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA
 * Method:    createDSA
 * Signature: ([B[B[B)J
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA_createDSA
  (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA
 * Method:    setKeys
 * Signature: (J[B[B)V
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA_setKeys
  (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);

/*
 * Class:     edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA
 * Method:    setPublicKey
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA_setPublicKey
  (JNIEnv *, jobject, jlong, jbyteArray);

/*
 * Class:     edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA
 * Method:    sign
 * Signature: (J[BII)[B
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA_sign
  (JNIEnv *, jobject, jlong, jbyteArray, jint, jint);

/*
 * Class:     edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA
 * Method:    verify
 * Signature: (J[B[BII)Z
 */
JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA_verify
  (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray, jint, jint);

/*
 * Class:     edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA
 * Method:    generateKey
 * Signature: (J)[[B
 */
JNIEXPORT jobjectArray JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA_generateKey
  (JNIEnv *, jobject, jlong);

/*
 * Class:     edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA
 * Method:    deleteDSA
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_digitalSignature_OpenSSLDSA_deleteDSA
  (JNIEnv *, jobject, jlong);

#ifdef __cplusplus
}
#endif
#endif
