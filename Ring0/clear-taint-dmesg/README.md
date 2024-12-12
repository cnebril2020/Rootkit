
## Hiding taint message from `/dev/kmsg` and `dmesg`.

This LKM hooks the read sycall to hide messages containing the word "taint" from `/dev/kmsg`, preventing this message from being read by the user.

Remembering this is a simple poc/demo, btw that the `dmesg` command uses `/dev/kmsg`, so it will automatically hide to `dmesg` too.
    
The output of `/dev/kmsg` is a bit messy (it shows everything on a single line), for dmesg it is normal, but this can be fixed.

<p align="center"><img src="image.png"></p>
