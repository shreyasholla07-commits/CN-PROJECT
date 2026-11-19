# Dynamic Host Blocking System (SDN, TCP)
Setup (Ubuntu 20.04 VM recommended):
  sudo apt install -y mininet openvswitch-switch python3-pip hping3
  pip3 install ryu eventlet==0.30.2
Run manually:
  T1: ryu-manager dynamic_blocker.py            (BLOCK_TIME=15 for short demo)
  T2: sudo python3 topo.py                      (Mininet CLI)
Run automated tests:
  T1: BLOCK_TIME=15 ryu-manager dynamic_blocker.py
  T2: sudo python3 run_tests.py
Cleanup: sudo mn -c
