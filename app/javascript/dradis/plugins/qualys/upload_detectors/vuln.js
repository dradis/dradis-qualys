import { register } from 'upload_detector_registry'

register({
  name: 'Dradis::Plugins::Qualys::Vuln',
  match: (sample) =>
    /qualysguard|qualys\.com.*scan-\d/.test(sample) ||
    /<SCAN\s+value="scan\//.test(sample)
})
