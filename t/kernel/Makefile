EXTRA_CFLAGS = $(DEFINES)

obj-m = kserver.o

all:
	        make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules 

clean:
	        make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
