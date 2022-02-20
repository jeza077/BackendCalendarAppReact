const { response } = require('express');
const bcrypt = require('bcryptjs');
const Usuario = require('../models/User');
const { generarJWT } = require('../helpers/jwt');


const createUser = async(req, res = response) => {

    const { email, password } = req.body;

    try {      
        // Validar que usuario no exista ya en DB  por medio del email que es unico
        let usuario = await Usuario.findOne({ email });
        
        if( usuario ){
            return res.status(400).json({
                ok: false,
                mgs: 'Un usuario ya existe con ese correo'
            });
        }

        usuario = new Usuario( req.body );

        // Encriptar password
        const salt = bcrypt.genSaltSync();
        usuario.password = bcrypt.hashSync( password, salt );
    
        await usuario.save();

        // Generar JWT
        const token = await generarJWT( usuario.id, usuario.name );
    
        res.status(201).json({
            ok: true,
            uid: usuario.id,
            name: usuario.name,
            token
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            ok: false,
            msg: 'Por favor contactese con el administrador'
        });
    }

};


const loginUser = async(req, res = response) => {

    const { email, password } = req.body;

    try {      
        // Validar que el email exista
        const usuario = await Usuario.findOne({ email });
        
        if( !usuario ){
            return res.status(400).json({
                ok: false,
                mgs: 'El usuario no existe con ese email.'
            });
        }

        // Confirmar los passwords
        const validPassword = bcrypt.compareSync( password, usuario.password );

        if( !validPassword ){
            return res.status(400).json({
                ok: false,
                msg: 'Password incorrecto.'
            });
        }

        // Generar JSON WEB TOKEN (JWT)
        const token = await generarJWT( usuario.id, usuario.name );


        res.json({
            ok: true,
            uid: usuario.id,
            name: usuario.name,
            token
        })


    } catch (error) {
        console.error(error);
        res.status(500).json({
            ok: false,
            msg: 'Por favor contactese con el administrador'
        });
    }

};

const revalidateToken = async(req, res = response) => {

    const { uid, name } = req;

    // Generar JSON WEB TOKEN (JWT)
    const token = await generarJWT( uid, name );

    res.json({
        ok: true,
        token
    });
};

module.exports = {
    createUser,
    loginUser,
    revalidateToken
}