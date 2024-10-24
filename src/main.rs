fn main() {
    Packet::pack_to_ax25("NJ7P", "N7LEM", 1, true, 2, Pid::NoL3, "Hello world");
}