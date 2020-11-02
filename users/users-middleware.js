const jwt = require("jsonwebtoken")

const roles = ["basic","admin"]

function restrict(role) {
	return async (req, res, next) => {
		try {
			// express-session will automatically get the session ID from the cookie
			// header, and check to make sure it's valid and the session for this user exists.
			// if (!req.session || !req.session.user) {
			// 	return res.status(401).json({
			// 		message: "Invalid credentials",
			// 	})
			// }

			// get the token value from a manual header and make sure it's not empty
			const token = req.headers.authorization
			if (!token) {
				return res.status(401).json({
					message: "Invalid credentials",
				})
			}

			//makes sure the signature on the token is valid and still matches the payload
			jwt.verify(token, process.env.JWT_SECRET, (err, decoded) =>{
				if (err) {
					return res.status(401).json({
						message: "Invalid credentials",
					})
				}
				
				// use an index based scale for checking permission rather than a hard
				// equality check, since adminds should still be able to access regular routes
				if (role && roles.indexOf(decoded.userRole) < roles.indexOf(role)){
					return res.status(401).json({
						message: "Invalid credentials",
					})
				}
				
				// make the token's decoded payload available to other middleware
				// functions or route handlers, in case we want to use it for something
				req.token = decoded

				// at this point we know the token is valid and the user is authorized
				next()
			})
		} catch(err) {
			next(err)
		}
	}
}

module.exports = {
	restrict,
}