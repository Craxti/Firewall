# Firewall System

The Firewall System is a Python-based application that provides network traffic filtering and security capabilities. It allows you to define rules based on conditions and actions to control the flow of network packets.

## Features

- Rule-based filtering: Define rules based on conditions and actions to control packet flow.
- Flexible conditions: Define conditions based on IP address, port number, protocol, and payload content.
- Versatile actions: Perform actions such as blocking, allowing, logging, modifying packets, redirecting, and more.
- Packet processing: Implement custom packet processors for advanced analysis and handling.
- Rule chaining: Process rules sequentially, allowing each rule's action to influence subsequent processing.
- Automated testing: Includes a test suite for automated testing of firewall functionality.

## Installation

1. Clone the repository: 

    `git clone https://github.com/your-username/firewall-system.git`

2. Navigate to the project directory:

    `cd firewall-system`

3. Install dependencies:

    `pip install -r requirements.txt`

## Usage

1. Import the necessary modules in your Python script:

   ```python
   from firewall import Firewall
   from rule import FirewallRule
   from condition import IPCondition, PortCondition
   from action import BlockAction, AllowAction, LogAction
   from packet_processor import CustomPacketProcessor
   
2. Start

   ``python main.py``


## Testing

The Firewall System includes a test suite for automated testing. To run the tests, use the following command:

    python -m unittest discover -s tests -p test_*.py

## Contributing

Contributions to the Firewall System are welcome! If you find any issues or have suggestions for improvements, please submit a pull request or open an issue in the GitHub repository.

## License

Copyright © Aleksandr
web - https://craxti.github.io/flask_site/

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the `GNU General Public License`_ for more details.


.. _GNU General Public License: https://www.gnu.org/licenses/gpl-3.0.html
