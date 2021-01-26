.PHONY: test clean

test: src/test/test-blgc

	$^

src/test/test-blgc: src/blgc/libblgc.a src/blst/libblst.a

	$(MAKE) -C src/test

src/blgc/libblgc.a:

	$(MAKE) -C src/blgc

src/blst/libblst.a:

	cd src/blst && ./build.sh

clean:

	$(MAKE) -C src/blgc clean
	$(MAKE) -C src/test clean
