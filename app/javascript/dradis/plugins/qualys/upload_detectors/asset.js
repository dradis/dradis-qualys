import { register } from 'upload_detector_registry'

register({
  name: 'Dradis::Plugins::Qualys::Asset',
  match: (sample) => /<ASSET_DATA_REPORT\b/.test(sample)
})
