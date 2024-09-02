import jwt from "jsonwebtoken";

//Middleware
export const verifyUser = (req, res, next) => {
  try {
    const token = req.cookies.token; // Debugging
    if (!token)
      return res.status(401).json({ Status: false, Error: "Non authentifié" });
    if (token) {
      jwt.verify(token, "jwt_secret_key", (err, decoded) => {
        if (err)
          return res
            .status(403)
            .json({ Status: false, Error: "Token invalide" });
        req.userId = decoded.id;
        req.role = decoded.role;
        next();
      });
    }
  } catch (error) {
    return res.status(500).json({
      Status: false,
      ErrorMessage: "Erreur du serveur. Veuillez réessayer plus tard.",
    });
  }
};

export const verifyIdIntegrity = (req, res, next) => {
  try {
    const role = req.role;
    const userIdFromToken = req.userId; // ID récupéré du token après authentification

    // Assurez-vous que les valeurs nécessaires existent
    if (!userIdFromToken || !role) {
      return res
        .status(400)
        .json({ Status: false, Error: "Erreur de Token, valeur absente" });
    }

    if (role !== "admin") {
      if (userIdFromToken.toString() !== req.params.id.toString()) {
        return res.status(403).json({ Status: false, Error: "Non autorisé" });
      }
    }
    next();
  } catch (error) {
    return res.status(500).json({
      Status: false,
      ErrorMessage: "Erreur du serveur. Veuillez réessayer plus tard.",
    });
  }
};

export const verifyAdminRole = (req, res, next) => {
  try {
    const role = req.role;
    if (!role) {
      return res
        .status(400)
        .json({ Status: false, Error: "Erreur de Token, valeur absente" });
    }

    if (role !== "admin") {
      return res.status(403).json({ Status: false, Error: "Non autorisé" });
    }
    next();
  } catch (error) {
    return res.status(500).json({
      Status: false,
      ErrorMessage: "Erreur du serveur. Veuillez réessayer plus tard.",
    });
  }
};
