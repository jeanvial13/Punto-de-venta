import es from './es';

export const translations = {
    es,
};

export type Language = 'es';

export const currentLanguage: Language = 'es';

export const t = (key: string): string => {
    const keys = key.split('.');
    let value: any = translations[currentLanguage];

    for (const k of keys) {
        value = value?.[k];
    }

    return value || key;
};

export default t;
