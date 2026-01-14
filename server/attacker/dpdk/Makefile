debug: clean
	meson setup ./build -DPROFILE=true && ninja -C build

short: clean
	meson setup ./build -DSHORT=true && ninja -C build

release: clean
	meson setup ./build --buildtype release && ninja -C build

run:
	sudo ./build/dpdk_qia $(pps) $(duration)

clean:
	-rm -rf build
