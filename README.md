# LayerTwoPing

[`layertwoping.py`](layertwoping.py) is a Python script that uses the Scapy library to send and receive Ethernet frames using the Ethernet Configuration Testing Protocol (ECTP). It can operate in both client and server modes to test Ethernet connectivity and measure round-trip times.

## Installation

1. **Clone the repository:**
    ```sh
    git clone <repository_url>
    cd <repository_directory>
    ```

2. **Install the required dependencies:**
    ```sh
    pip install -r requirements.txt
    ```

    Ensure that `scapy` is installed. If not, you can install it using:
    ```sh
    pip install scapy
    ```

3. **Run the script with root privileges:**
    ```sh
    sudo python layertwoping.py
    ```

## Usage

### Client Mode

In client mode, the script sends ECTP packets to a specified target MAC address and listens for responses.

1. **Run the script:**
    ```sh
    sudo python layertwoping.py
    ```

2. **Select Client mode:**
    ```
    Select mode:
    1. Client mode
    2. Server mode
    Enter choice (1/2): 1
    ```

3. **Choose an Ethernet interface:**
    ```
    Available interfaces:
    1. eth0
    2. wlan0
    Select an interface (number): 1
    ```

4. **Enter the target MAC address:**
    ```
    Enter target MAC address (e.g., 00:11:22:33:44:55): 00:11:22:33:44:55
    ```

The client will start sending ECTP packets to the target MAC address and print the received responses along with round-trip times.

### Server Mode

In server mode, the script listens for incoming ECTP packets on a specified interface and sends response packets back to the source.

1. **Run the script:**
    ```sh
    sudo python layertwoping.py
    ```

2. **Select Server mode:**
    ```
    Select mode:
    1. Client mode
    2. Server mode
    Enter choice (1/2): 2
    ```

3. **Choose an Ethernet interface:**
    ```
    Available interfaces:
    1. eth0
    2. wlan0
    Select an interface (number): 1
    ```

The server will start listening for ECTP packets on the selected interface and send responses to the source MAC address.

## Notes

- This script requires root privileges to send and receive raw Ethernet frames. Ensure you run it with `sudo`.
- The script uses a fixed payload length of 64 bytes and a response delay of 0.05 seconds for debugging purposes. You can adjust these values by modifying the `FIXED_PAYLOAD_LENGTH` and `RESPONSE_DELAY` constants in the script.

## License

This project is licensed under the MIT License. See the LICENSE file for details.