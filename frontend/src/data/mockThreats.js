const mockThreats = [
  // severity 5 - critical
  { flow_id: 1,  proto: 'tcp', service: 'irc', conn_state: 'S3', confidence: 0.997, attack_type: 'C&C-Mirai', severity: 5, orig_bytes: 0, resp_bytes: 0, duration: 0.000003, orig_pkts: 2, resp_pkts: 0, missed_bytes: 0 },
  { flow_id: 2,  proto: 'tcp', service: 'ftp', conn_state: 'SF', confidence: 0.991, attack_type: 'FileDownload', severity: 5, orig_bytes: 45231, resp_bytes: 0, duration: 1.24, orig_pkts: 38, resp_pkts: 0, missed_bytes: 0 },
  { flow_id: 3,  proto: 'tcp', service: 'irc', conn_state: 'SF', confidence: 0.988, attack_type: 'C&C-Mirai', severity: 5, orig_bytes: 512, resp_bytes: 128, duration: 0.45, orig_pkts: 6, resp_pkts: 3, missed_bytes: 0 },
  { flow_id: 4,  proto: 'tcp', service: 'ftp-data', conn_state: 'SF', confidence: 0.976, attack_type: 'FileDownload', severity: 5, orig_bytes: 18900, resp_bytes: 0, duration: 0.88, orig_pkts: 22, resp_pkts: 0, missed_bytes: 0 },

  // severity 4 - high
  { flow_id: 5,  proto: 'tcp', service: 'ssh', conn_state: 'RSTO', confidence: 0.967, attack_type: 'Mirai', severity: 4, orig_bytes: 0, resp_bytes: 0, duration: 0.12, orig_pkts: 4, resp_pkts: 2, missed_bytes: 0 },
  { flow_id: 6,  proto: 'tcp', service: 'http', conn_state: 'SF', confidence: 0.954, attack_type: 'C&C-HeartBeat-Attack', severity: 4, orig_bytes: 240, resp_bytes: 180, duration: 0.31, orig_pkts: 5, resp_pkts: 4, missed_bytes: 0 },
  { flow_id: 7,  proto: 'tcp', service: 'ssh', conn_state: 'SF', confidence: 0.943, attack_type: 'C&C-Mirai', severity: 4, orig_bytes: 1024, resp_bytes: 512, duration: 2.1, orig_pkts: 12, resp_pkts: 8, missed_bytes: 0 },
  { flow_id: 8,  proto: 'tcp', service: 'ssl', conn_state: 'SF', confidence: 0.931, attack_type: 'C&C-HeartBeat-Attack', severity: 4, orig_bytes: 320, resp_bytes: 210, duration: 0.55, orig_pkts: 7, resp_pkts: 5, missed_bytes: 0 },
  { flow_id: 9,  proto: 'tcp', service: 'http', conn_state: 'S0', confidence: 0.918, attack_type: 'C&C-HeartBeat-Attack', severity: 4, orig_bytes: 0, resp_bytes: 0, duration: 0.001, orig_pkts: 2, resp_pkts: 0, missed_bytes: 0 },

  // severity 3 - medium
  { flow_id: 10, proto: 'tcp', service: 'Unknown', conn_state: 'S0', confidence: 0.996, attack_type: 'PartOfAHorizontalPortScan-Attack', severity: 3, orig_bytes: 0, resp_bytes: 0, duration: 0.000003, orig_pkts: 2, resp_pkts: 0, missed_bytes: 0 },
  { flow_id: 11, proto: 'udp', service: 'Unknown', conn_state: 'S0', confidence: 0.984, attack_type: 'DDoS', severity: 3, orig_bytes: 0, resp_bytes: 0, duration: 0.0, orig_pkts: 1, resp_pkts: 0, missed_bytes: 0 },
  { flow_id: 12, proto: 'tcp', service: 'Unknown', conn_state: 'RSTO', confidence: 0.971, attack_type: 'Okiru', severity: 3, orig_bytes: 0, resp_bytes: 0, duration: 0.05, orig_pkts: 3, resp_pkts: 1, missed_bytes: 0 },
  { flow_id: 13, proto: 'tcp', service: 'Unknown', conn_state: 'RSTR', confidence: 0.958, attack_type: 'Okiru', severity: 3, orig_bytes: 0, resp_bytes: 0, duration: 0.03, orig_pkts: 2, resp_pkts: 1, missed_bytes: 0 },
  { flow_id: 14, proto: 'udp', service: 'dns', conn_state: 'SF', confidence: 0.934, attack_type: 'C&C-HeartBeat', severity: 3, orig_bytes: 128, resp_bytes: 64, duration: 0.02, orig_pkts: 2, resp_pkts: 1, missed_bytes: 0 },
  { flow_id: 15, proto: 'tcp', service: 'Unknown', conn_state: 'OTH', confidence: 0.921, attack_type: 'PartOfAHorizontalPortScan-Attack', severity: 3, orig_bytes: 0, resp_bytes: 0, duration: 0.0, orig_pkts: 1, resp_pkts: 0, missed_bytes: 0 },

  // severity 2 - low
  { flow_id: 16, proto: 'tcp', service: 'Unknown', conn_state: 'REJ', confidence: 0.912, attack_type: 'PartOfAHorizontalPortScan', severity: 2, orig_bytes: 0, resp_bytes: 0, duration: 0.0, orig_pkts: 1, resp_pkts: 1, missed_bytes: 0 },
  { flow_id: 17, proto: 'icmp', service: 'Unknown', conn_state: 'OTH', confidence: 0.897, attack_type: 'PartOfAHorizontalPortScan', severity: 2, orig_bytes: 0, resp_bytes: 0, duration: 0.0, orig_pkts: 1, resp_pkts: 0, missed_bytes: 0 },
  { flow_id: 18, proto: 'tcp', service: 'Unknown', conn_state: 'RSTOS0', confidence: 0.876, attack_type: 'PartOfAHorizontalPortScan', severity: 2, orig_bytes: 0, resp_bytes: 0, duration: 0.0, orig_pkts: 1, resp_pkts: 0, missed_bytes: 0 },
  { flow_id: 19, proto: 'icmp', service: 'Unknown', conn_state: 'OTH', confidence: 0.854, attack_type: 'PartOfAHorizontalPortScan', severity: 2, orig_bytes: 0, resp_bytes: 0, duration: 0.0, orig_pkts: 1, resp_pkts: 0, missed_bytes: 0 },
  { flow_id: 20, proto: 'tcp', service: 'Unknown', conn_state: 'REJ', confidence: 0.831, attack_type: 'PartOfAHorizontalPortScan', severity: 2, orig_bytes: 0, resp_bytes: 0, duration: 0.0, orig_pkts: 1, resp_pkts: 1, missed_bytes: 0 },
];

export default mockThreats;
