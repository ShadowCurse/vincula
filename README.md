# Vincula

## Experimental linux container implementation in Rust

Based on the [Litchi Pi article](https://litchipi.github.io/series/container_in_rust) and [the original tutorial](https://blog.lizzie.io/linux-containers-in-500-loc.html)

## Usage 

To build run:
```sh
$ cargo build
```

Launch options can be acessed via 
```sh
$ vincula --help
```

To launch container run:
```sh
$ sudo vincula -d -c {COMMAND} -u {UID} -m {MOUNT_DIR} --hostname {HOSTNAME} -a {ADDITIONAL_MOUNT_PATH}:{PATH_IN_CONTAINER}
```
