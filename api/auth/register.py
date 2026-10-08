methods = ["POST"]

csrf_exempt = True


swagger = {
    "summary": "Registrar usuario",

    "description": "Registra un nuevo usuario en el sistema.",

    "tags": [
        "Auth"
    ],

    "request_body": {
        "required": True,
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "username": {
                            "type": "string",
                            "example": "zerox"
                        },
                        "email": {
                            "type": "string",
                            "format": "email",
                            "example": "test@test.com"
                        },
                        "password": {
                            "type": "string",
                            "format": "password",
                            "example": "12345678"
                        }
                    },
                    "required": [
                        "username",
                        "email",
                        "password"
                    ]
                }
            }
        }
    },

    "responses": {
        "201": {
            "description": "Usuario registrado correctamente."
        },
        "422": {
            "description": "Datos inválidos."
        },
        "409": {
            "description": "Usuario o correo ya registrado."
        }
    }
}


def endpoint(request, response):

    return response.json(
        {
            "success": True,
            "message": "Usuario registrado correctamente."
        },
        201
    )