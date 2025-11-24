export const MESSAGES = {
    // Auth
    AUTH: {
        INVALID_CREDENTIALS: 'Credenciales inválidas',
        USER_CREATED: 'Usuario creado exitosamente',
        LOGIN_SUCCESS: 'Inicio de sesión exitoso',
        UNAUTHORIZED: 'No autorizado',
        TOKEN_EXPIRED: 'Token expirado',
    },

    // Products
    PRODUCTS: {
        CREATED: 'Producto creado exitosamente',
        UPDATED: 'Producto actualizado exitosamente',
        DELETED: 'Producto eliminado exitosamente',
        NOT_FOUND: 'Producto no encontrado',
        LOW_STOCK: 'Stock bajo',
        OUT_OF_STOCK: 'Sin stock',
    },

    // Sales
    SALES: {
        CREATED: 'Venta registrada exitosamente',
        CANCELED: 'Venta cancelada',
        INSUFFICIENT_STOCK: 'Stock insuficiente para el producto',
        INVALID_PAYMENT: 'Método de pago inválido',
    },

    // Repairs
    REPAIRS: {
        CREATED: 'Orden de reparación creada exitosamente',
        UPDATED: 'Reparación actualizada exitosamente',
        STATUS_CHANGED: 'Estado cambiado a',
        DELIVERED: 'Reparación entregada al cliente',
        CANCELED: 'Reparación cancelada',
        NOT_FOUND: 'Reparación no encontrada',
        PART_ADDED: 'Repuesto agregado a la reparación',
        SOFTWARE_ADDED: 'Servicio de software agregado',
        NOTE_ADDED: 'Nota agregada',
    },

    // Devices
    DEVICES: {
        REGISTERED: 'Dispositivo registrado exitosamente',
        NOT_FOUND: 'Dispositivo no encontrado',
        PHOTO_UPLOADED: 'Foto subida exitosamente',
    },

    // Technicians
    TECHNICIANS: {
        CREATED: 'Técnico creado exitosamente',
        UPDATED: 'Técnico actualizado exitosamente',
        NOT_FOUND: 'Técnico no encontrado',
    },

    // Inventory
    INVENTORY: {
        LOG_CREATED: 'Movimiento de inventario registrado',
        STOCK_UPDATED: 'Stock actualizado',
    },

    // Cash Register
    CASH_REGISTER: {
        OPENED: 'Caja abierta exitosamente',
        CLOSED: 'Caja cerrada exitosamente',
        ALREADY_OPEN: 'El usuario ya tiene una caja abierta',
        NOT_FOUND: 'Caja no encontrada',
        ALREADY_CLOSED: 'La caja ya está cerrada',
    },

    // General
    GENERAL: {
        SUCCESS: 'Operación exitosa',
        ERROR: 'Error en la operación',
        NOT_FOUND: 'No encontrado',
        VALIDATION_ERROR: 'Error de validación',
        INTERNAL_ERROR: 'Error interno del servidor',
    },

    // Repair Statuses
    REPAIR_STATUS: {
        RECEIVED: 'Recibido',
        DIAGNOSING: 'En Diagnóstico',
        AWAITING_PARTS: 'Esperando Repuestos',
        IN_REPAIR: 'En Reparación',
        SOFTWARE_REPAIR: 'Reparación de Software',
        QUALITY_CHECK: 'Control de Calidad',
        READY_FOR_PICKUP: 'Listo para Entregar',
        DELIVERED: 'Entregado',
        CANCELED: 'Cancelado',
    },

    // Payment Methods
    PAYMENT_METHODS: {
        CASH: 'Efectivo',
        CARD: 'Tarjeta',
        TRANSFER: 'Transferencia',
        MIXED: 'Mixto',
    },

    // Roles
    ROLES: {
        ADMIN: 'Administrador',
        CASHIER: 'Cajero',
        SUPERVISOR: 'Supervisor',
        INVENTORY: 'Inventario',
    },
};
