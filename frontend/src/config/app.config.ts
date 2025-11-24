export const APP_CONFIG = {
    name: 'VICMAN',
    fullName: 'VICMAN - Sistema de Punto de Venta y Reparaciones',
    version: '1.0.0',
    language: 'es',
    currency: 'MXN',
    currencySymbol: '$',
    timezone: 'America/Mexico_City',

    // Company Info (editable via Settings)
    company: {
        name: 'VICMAN',
        address: '',
        phone: '',
        email: '',
        website: '',
        logo: '/assets/logo.png',
    },

    // Default Tax Rate
    defaultTaxRate: 16, // 16% IVA

    // Pagination
    pagination: {
        defaultPageSize: 10,
        pageSizeOptions: [10, 25, 50, 100],
    },

    // Date Formats
    dateFormats: {
        short: 'DD/MM/YYYY',
        long: 'DD de MMMM de YYYY',
        withTime: 'DD/MM/YYYY HH:mm',
    },
};

export default APP_CONFIG;
