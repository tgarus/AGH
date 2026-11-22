import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

import enCommon from './locales/en/common.json';
import plCommon from './locales/pl/common.json';

void i18n.use(initReactI18next).init({
  resources: {
    pl: { common: plCommon },
    en: { common: enCommon },
  },
  lng: 'pl',
  fallbackLng: 'en',
  defaultNS: 'common',
  interpolation: {
    escapeValue: false,
  },
});

export default i18n;
