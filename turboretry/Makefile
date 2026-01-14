build: clean
	meson ./build && ninja -C ./build

debug: clean
	meson ./build -DLOG_LEVEL=trace -DPROFILE=true -DDEBUG=true && ninja -C ./build

profile: clean
	meson ./build --buildtype debugoptimized -DLOG_LEVEL=info -DPROFILE=true && ninja -C ./build

rprofile: clean
	meson ./build --buildtype release -DLOG_LEVEL=info -DPROFILE=true && ninja -C ./build

base: clean
	meson ./build -DLOG_LEVEL=warning && ninja -C ./build

release: clean
	meson ./build --buildtype release -DLOG_LEVEL=warning && ninja -C ./build

clean:
	rm -rf ./build ./builddir

run-debug:
	bash run_app.sh --app_level info

run-test:
	bash run_app.sh --app_level warn

tprofile: clean
	meson ./build --buildtype debugoptimized -DTOP_PROFILE=true && ninja -C ./build

test: clean
	meson ./build --buildtype debugoptimized && ninja -C ./build

count:
	@echo "Lines of code (LOC):"
	@find . -type f \( -name "*.c" -o -name "*.h" \) -exec wc -l {} + | awk '{sum += $$1} END {print sum}'