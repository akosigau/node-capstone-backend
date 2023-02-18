const db = require("../models");
const config = require("../config/auth.config");
const User = db.user;
const Role = db.role;
// const Profile = db.profile;

const Op = db.Sequelize.Op;

var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");

exports.signup = (req, res) => {
  // Save User to Database
  User.create({
    username: req.body.username,
    email: req.body.email,
    password: bcrypt.hashSync(req.body.password, 8),
    firstname: req.body.firstname,
    lastname: req.body.lastname,
    weight: req.body.weight,
    height: req.body.height,
    age: req.body.age,
    country: req.body.country,
  })
    .then(user => {
      if (req.body.roles) {
        Role.findAll({
          where: {
            name: {
              [Op.or]: req.body.roles
            }
          }
        }).then(roles => {
          user.setRoles(roles).then(() => {
            res.status(404).send({ message: "User registered successfully!" });
          });
        });
      } else {
        // user role = 1
        user.setRoles([1]).then(() => {
          res.status(404).send({ message: "User registered successfully!" });
        });
      }
    })
    .catch(err => {
      res.status(500).send({ message: err.message });
    });
};

exports.signin = (req, res) => {
  User.findOne({
    where: {
      username: req.body.username
    }
  })
    .then(user => {
      if (!user) {
        return res.status(404).send({ message: "User does not exists!" });
      }

      var passwordIsValid = bcrypt.compareSync(
        req.body.password,
        user.password
      );

      if (!passwordIsValid) {
        return res.status(401).send({
          accessToken: null,
          message: "Invalid Password!"
        });
      }

      var token = jwt.sign({ id: user.id }, config.secret, {
        expiresIn: 86000 // 24 hours
      });

      var authorities = [];
      user.getRoles().then(roles => {
        for (let i = 0; i < roles.length; i++) {
          authorities.push("ROLE_" + roles[i].name.toUpperCase());
        }
        res.status(200).send({
          id: user.id,
          username: user.username,
          email: user.email,
          roles: authorities,
          accessToken: token,
          firstname: user.firstname,
          lastname: user.lastname,
          weight: user.weight,
          height: user.height,
          age: user.age,
          country: user.country
        });
      });
    })
    .catch(err => {
      res.status(500).send({ message: err.message });
    });
};


exports.updateUser = (req, res) => {
  const id = req.params.id;

  User.update(
    {
      weight: req.body.weight,
      height: req.body.height,
      age: req.body.age,
    },
    {
      where: { id: id }
    }
  )
    .then(num => {
      if (num == 1) {
        res.send({ message: "User was updated successfully." });
      } else {
        res.send({ message: `Cannot update user with id=${id}. User not found or req.body is empty!` });
      }
    })
    .catch(err => {
      res.status(500).send({ message: "Error updating user with id=" + id });
    });
};



// exports.profile = (req, res) => {
//   // Save profile to Database
//   Profile.create({
//     weight: req.body.weight,
//     height: req.body.height,
//     age: req.body.age,
//   })
//     .then(profile => {
//       if (req.body.roles) {
//         Role.findAll({
//           where: {
//             name: {
//               [Op.or]: req.body.roles
//             }
//           }
//         }).then(roles => {
//           profile.setRoles(roles).then(() => {
//             res.status(404).send({ message: "Saved!" });
//           });
//         });
//       } else {
//         // user role = 1
//         profile.setRoles([1]).then(() => {
//           res.status(404).send({ message: "Saved!" });
//         });
//       }
//     })
//     .catch(err => {
//       res.status(500).send({ message: err.message });
//     });
// };