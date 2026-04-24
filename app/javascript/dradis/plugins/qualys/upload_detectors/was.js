import { register } from 'upload_detector_registry'

register({
  name: 'Dradis::Plugins::Qualys::WAS',
  match: (sample) => /<WAS_SCAN_REPORT\b/.test(sample)
})
