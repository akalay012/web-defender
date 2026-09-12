"""Sensor ownership registry."""
SENSOR_FAMILIES={
 "browser_observation":"AcquisitionSensorsMixin.run_browser_worker",
 "content_acquisition":"AcquisitionSensorsMixin.finalize_content_acquisition_v32316",
 "html":"AcquisitionSensorsMixin.check_html",
 "static_source":"AcquisitionSensorsMixin.static_source_intelligence_v32317",
 "javascript_dataflow":"AcquisitionSensorsMixin.trace_javascript_dataflow",
 "differential_observation":"AcquisitionSensorsMixin.differential_observation_engine_v32331",
 "dns":"AcquisitionSensorsMixin.check_dns",
 "tls":"AcquisitionSensorsMixin.check_ssl_certificate",
}
