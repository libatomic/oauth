package server

import (
	"context"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignValue(t *testing.T) {
	badKey := *testKey

	badKey.E = 99

	tests := map[string]struct {
		privKey        *rsa.PrivateKey
		key            string
		val            interface{}
		expectedError  error
		expectedResult string
	}{
		"TestSignValueBadValue": {
			privKey:       testKey,
			key:           AuthRequestParam,
			val:           make(chan int),
			expectedError: errors.New("json: unsupported type: chan int"),
		},
		"TestSignValueBadKey": {
			privKey:       &badKey,
			key:           AuthRequestParam,
			val:           struct{}{},
			expectedError: errors.New("rsa: internal error"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			res, err := signValue(context.TODO(), test.privKey, test.key, test.val)

			if test.expectedError != nil {
				if assert.Error(t, err) {
					assert.EqualError(t, err, test.expectedError.Error(), err)
				}
			} else {
				assert.Equal(t, test.expectedResult, res)
			}
		})
	}
}

// expectedResult: "eyJGb28iOiJiYXIifQ.lZTpWcU0MLFGNNUXE6xYgewczZL_3j9sew8rF2Db7kZWbb3k6TMthqga3mQNaeK6bAmoWkjvtbjJlVlUjhYx2xbMukUKDkj19BmEapjgn0Wj1ZQzsR7TjOaVYgfvV0Yixq2EGuY98pARLz05J_RAavK5ieyHxtovmO7moP7KN3vDdInr_9OwpZ2vMbq91m7KkVbe6GcbIaa3cJNqtArXjrVDEVgE7VCTU7ShH3b48jMy1jp4CGNX9p72_msg7Aoy_W0VOdjXcAo3gxGBAQwEdd0XLp6J-AlHnd4-meLRM4C8W438rlqcyygKAm6Y_NIa5Iz2FGdUjkAhXeISDvbfPA",

func TestVerifyValue(t *testing.T) {
	badKey := testKey.PublicKey

	badKey.E = -99

	tests := map[string]struct {
		pubKey         *rsa.PublicKey
		key            string
		val            string
		expectedError  error
		expectedResult string
		out            struct {
			Foo string
		}
	}{
		"TestVerifyBadValue": {
			pubKey:        &testKey.PublicKey,
			key:           AuthRequestParam,
			val:           "foo.bar/x0329",
			expectedError: errors.New("illegal base64 data at input byte 3"),
		},
		"TestVerifyBadKey": {
			pubKey:        &badKey,
			key:           AuthRequestParam,
			val:           "foo.bar",
			expectedError: errors.New("crypto/rsa: verification error"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := verifyValue(context.TODO(), test.pubKey, test.key, test.val, &test.out)
			if assert.Error(t, err) {
				assert.EqualError(t, err, test.expectedError.Error(), err)
			}
		})
	}
}
