# extension

The Mullvad Browser MV2 extension that picks a route per request (Tor / I2P / Nym mixnet / Direct) and instructs the browser to use the matching localhost port (8881 for Tor in v1).

**The routing decision lives here**, not in the data plane. Chromium browsers are explicitly unsupported.
