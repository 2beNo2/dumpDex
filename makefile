

all:
	rm -rf ./obj
	adb push ./libs/armeabi-v7a/dumpDex /data/local/tmp/dumpDex
	adb shell chmod 777 /data/local/tmp/dumpDex
	adb shell /data/local/tmp/dumpDex

arm64:
	rm -rf ./obj
	adb push ./libs/arm64-v8a/dumpDex /data/local/tmp/dumpDex
	adb shell chmod 777 /data/local/tmp/dumpDex
	adb shell /data/local/tmp/dumpDex

clean:
	rm -rf ./obj
	rm -rf ./libs