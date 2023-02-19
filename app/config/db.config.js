module.exports = {
    HOST: "https://sthenos-backend.onrender.com",
    USER: "root",
    PASSWORD: "",
    DB: "sthenosdb",
    dialect: "mysql",
    pool: {
      max: 5,
      min: 0,
      acquire: 30000,
      idle: 10000
    }
  };
  