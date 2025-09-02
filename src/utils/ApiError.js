class ApiError extends Error {
    constructor(
        statusCode,
        error = [],
        message = "Something went wrong",
        stack = "",
    ) {
        super(message)
        this.statusCode = statusCode
        this.data = null
        this.success = false
        this.message = message
        this.errors = error
    

    if(stack) {
        this.stack = stack
    } else {
        Error.captureStackTrace(this, this.constructor)
    }
}
}

export { ApiError }