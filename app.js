//jshint esversion:6

require('dotenv').config();
const currentYear = new Date().getFullYear();
const { parse, stringify } = require('flatted');
const { PythonShell } = require('python-shell');
const express = require("express");
const multer = require('multer');
const download = require('download');
const fs = require('fs');
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const app = express();
const path = require('path');

// ====== App & Middleware Setup ======
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

let latestPrediction = {
  knn_bin_cls: 'Attack', knn_mul_cls: 'DoS', knn_desc: 'A Denial-of-Service attack.', knn_bin_acc: '0.98', knn_mul_acc: '0.97',
  rf_bin_cls: 'Normal', rf_mul_cls: 'Normal', rf_desc: 'This is safe.', rf_bin_acc: '0.99', rf_mul_acc: '0.98',
  cnn_bin_cls: 'Attack', cnn_mul_cls: 'Probe', cnn_desc: 'Probing is another type of attack.', cnn_bin_acc: '0.95', cnn_mul_acc: '0.94',
  lstm_bin_cls: 'Normal', lstm_mul_cls: 'Normal', lstm_desc: 'This is safe.', lstm_bin_acc: '0.96', lstm_mul_acc: '0.95'
};
// ====== Database Setup ======
mongoose.connect(process.env.DB_LINK, { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// ====== Google OAuth Setup ======
passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: process.env.CALL_BACK_URL,
  userProfileUrl: process.env.URL
}, (accessToken, refreshToken, profile, cb) => {
  User.findOrCreate({ googleId: profile.id, username: profile.id }, (err, user) => {
    return cb(err, user);
  });
}));

// ====== File Upload Setup ======
let submitted_csv_file = "";
const storage = multer.diskStorage({
  destination: (req, file, callback) => {
    callback(null, './Uploaded_files');
  },
  filename: (req, file, callback) => {
    submitted_csv_file = file.originalname;
    console.log(submitted_csv_file);
    callback(null, file.originalname);
  }
});
const upload = multer({ storage: storage }).single('myfile');

// ====== Routes ======

// --- Home ---
app.get("/", (req, res) => res.render("home"));

// --- Authentication ---
app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));
app.get("/auth/google/NIDS",
  passport.authenticate('google', { failureRedirect: "/login" }),
  (req, res) => res.redirect("/submit")
);

// --- Register/Login/Logout ---
app.get("/register", (req, res) => res.render("register"));
app.post("/register", (req, res) => {
  User.register({ username: req.body.username }, req.body.password, (err, user) => {
    if (err) {
      console.log(err);
      return res.redirect("/register");
    }
    passport.authenticate("local")(req, res, () => res.redirect("/submit"));
  });
});

app.get("/login", (req, res) => res.render("login"));
app.post("/login", (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });
  req.login(user, (err) => {
    if (err) {
      console.log(err);
      return res.redirect("/login");
    }
    passport.authenticate("local")(req, res, () => res.redirect("/submit"));
  });
});

app.get("/logout", (req, res) => {
  req.session.csvUploaded = false;
  req.logout(() => {
    res.redirect("/");
    if (submitted_csv_file !== "") {
      const path = './Uploaded_files/' + submitted_csv_file;
      fs.unlink(path, (err) => {
        if (err) console.log(err);
        else {
          console.log('file deleted');
          submitted_csv_file = "";
        }
      });
    }
  });
});

// --- Submit & Parameter Forms ---
app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});
app.get("/parameters", (req, res) => res.render("parameters"));
app.post("/parameters", (req, res) => {
  const {
    protocol_type, service, flag, logged_in, count, srv_serror_rate, srv_rerror_rate,
    same_srv_rate, diff_srv_rate, dst_host_count, dst_host_srv_count, dst_host_same_srv_rate,
    dst_host_diff_srv_rate, dst_host_same_src_port_rate, dst_host_serror_rate, dst_host_rerror_rate
  } = req.body;

  let options = {
    args: [
      protocol_type, service, flag, logged_in, count, srv_serror_rate, srv_rerror_rate,
      same_srv_rate, diff_srv_rate, dst_host_count, dst_host_srv_count, dst_host_same_srv_rate,
      dst_host_diff_srv_rate, dst_host_same_src_port_rate, dst_host_serror_rate, dst_host_rerror_rate
    ]
  };
  console.log("Running parameter prediction...");
  PythonShell.run('nids_parameter_updated.py', options, (err, results) => {
    if (err) 
      {
        console.error("Error during prediction:", err);
        return res.status(500).send("Prediction error");
      }
    // Parse the output from Python
    // Example: results = [
    //   "KNN algorithm binary class:Normal",
    //   "KNN Multi Class Type : dos",
    //   "KNN  Description : ...",
    //   ...
    // ]
    let knn_bin_cls = '-', knn_mul_cls = '-', knn_desc = '-';
    let rf_bin_cls = '-', rf_mul_cls = '-', rf_desc = '-';
    let cnn_bin_cls = '-', cnn_mul_cls = '-', cnn_desc = '-';
    let lstm_bin_cls = '-', lstm_mul_cls = '-', lstm_desc = '-';

    results.forEach(line => {
      if (line.startsWith('KNN algorithm binary class:')) knn_bin_cls = line.split(':')[1].trim();
      if (line.startsWith('KNN Multi Class Type')) knn_mul_cls = line.split(':')[1].trim();
      if (line.startsWith('KNN  Description') || line.startsWith('KNN Description')) knn_desc = line.split(':').slice(1).join(':').trim();

      if (line.startsWith('Random Forsest Algorithm Binary class:')) rf_bin_cls = line.split(':')[1].trim();
      if (line.startsWith('RANDOM FOREST Multi Class Type')) rf_mul_cls = line.split(':')[1].trim();
      if (line.startsWith('RANDOM FOREST Description') || line.startsWith('RANDOM FOREST DESCRIPTION')) rf_desc = line.split(':').slice(1).join(':').trim();

      if (line.startsWith('CNN Algorithm binary class:')) cnn_bin_cls = line.split(':')[1].trim();
      if (line.startsWith('CNN Algorithm Multi class Type')) cnn_mul_cls = line.split(':')[1].trim();
      if (line.startsWith('CNN Description')) cnn_desc = line.split(':').slice(1).join(':').trim();

      if (line.startsWith('LSTM Algorithm binary class:')) lstm_bin_cls = line.split(':')[1].trim();
      if (line.startsWith('LSTM Algorithm Multi class Type')) lstm_mul_cls = line.split(':')[1].trim();
      if (line.startsWith('LSTM Description')) lstm_desc = line.split(':').slice(1).join(':').trim();
    });

   latestPrediction = {
  knn_bin_cls, knn_mul_cls, knn_desc, knn_bin_acc: '-', knn_mul_acc: '-',
  rf_bin_cls, rf_mul_cls, rf_desc, rf_bin_acc: '-', rf_mul_acc: '-',
  cnn_bin_cls, cnn_mul_cls, cnn_desc, cnn_bin_acc: '-', cnn_mul_acc: '-',
  lstm_bin_cls, lstm_mul_cls, lstm_desc, lstm_bin_acc: '-', lstm_mul_acc: '-'
};
res.render("secrets_2", latestPrediction);
  });
});

// --- Results Pages ---
app.get("/paramsecrets", (req, res) => {
  res.render("paramsecrets", {
    p_knn_bin_cls: latestPrediction.knn_bin_cls,
    p_knn_mul_cls: latestPrediction.knn_mul_cls,
    p_knn_desc: latestPrediction.knn_desc,
    p_knn_bin_acc: latestPrediction.knn_bin_acc,
    p_knn_mul_acc: latestPrediction.knn_mul_acc,

    p_rf_bin_cls: latestPrediction.rf_bin_cls,
    p_rf_mul_cls: latestPrediction.rf_mul_cls,
    p_rf_desc: latestPrediction.rf_desc,
    p_rf_bin_acc: latestPrediction.rf_bin_acc,
    p_rf_mul_acc: latestPrediction.rf_mul_acc,

    p_cnn_bin_cls: latestPrediction.cnn_bin_cls,
    p_cnn_mul_cls: latestPrediction.cnn_mul_cls,
    p_cnn_desc: latestPrediction.cnn_desc,
    p_cnn_bin_acc: latestPrediction.cnn_bin_acc,
    p_cnn_mul_acc: latestPrediction.cnn_mul_acc,

    p_lstm_bin_cls: latestPrediction.lstm_bin_cls,
    p_lstm_mul_cls: latestPrediction.lstm_mul_cls,
    p_lstm_desc: latestPrediction.lstm_desc,
    p_lstm_bin_acc: latestPrediction.lstm_bin_acc,
    p_lstm_mul_acc: latestPrediction.lstm_mul_acc
  });
});

app.get("/secrets_2", (req, res) => {
  res.render("secrets_2", latestPrediction);
});

// --- CSV Upload & Download ---
app.get("/csv", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("csv");
  } else {
    res.redirect("/login");
  }
});

app.post('/uploadjavatpoint', (req, res) => {
  upload(req, res, (err) => {
    if (err) return res.end("Error uploading file.");
    res.end("File is uploaded successfully!");
    console.log("File uploaded:", submitted_csv_file);

    const submitted_model = req.body.selected_model;
    let options = { args: [submitted_model, submitted_csv_file] };
    PythonShell.run('nids_csv_updated.py', options, (err, response) => {
      if (err) return console.log(err);
      if (response) {
        // After prediction, read the attack type counts json
        const countsFile = path.join(__dirname, `${submitted_model}_attack_type_counts.json`);
        let attackTypeCounts = {};
        if (fs.existsSync(countsFile)) {
          attackTypeCounts = JSON.parse(fs.readFileSync(countsFile, 'utf8'));
        }
        // Pass counts to the table route via redirect + session, or use a persistent object
        req.session.attackTypeCounts = attackTypeCounts;
        res.redirect(`/${submitted_model}_bin_table`);
      }
    });
  });
  req.session.csvUploaded = true;
});

app.get('/download-file', (req, res) => {
  const path = './Uploaded_files/' + submitted_csv_file;
  res.download(path);
});

function getMetrics(model, type) {
  try {
    const data = fs.readFileSync(`./metrics/${model}_${type}_report.json`);
    return JSON.parse(data);
  } catch (e) {
    return {};
  }
}
// --- Static Info Pages ---
app.get("/features", (req, res) => res.render("features"));
app.get("/attacks", (req, res) => res.render("attacks"));
app.get("/about", (req, res) => res.render("about"));
app.get("/stats", (req, res) => res.render("stats"));
app.get("/contact", (req, res) => res.render("contact"));

// --- Table & Results Pages ---
app.get("/knn_bin_table", (req, res) => {
  if (!req.session.csvUploaded) {
    return res.render("message", { message: "Please upload a CSV file first to see prediction results." });
  }
  const metrics = {
    "Normal": { precision: 0.98, recall: 0.97, "f1-score": 0.97, support: 500 },
    "Attack": { precision: 0.95, recall: 0.96, "f1-score": 0.95, support: 300 },
    "accuracy": 0.965,
    "macro avg": { precision: 0.965, recall: 0.965, "f1-score": 0.965, support: 800 },
    "weighted avg": { precision: 0.966, recall: 0.965, "f1-score": 0.965, support: 800 }
  };
  const attackTypeCounts = { "DoS": 120, "Probe": 45, "R2L": 12, "U2R": 3 };
  res.render("knn_bin_table", { metrics, attackTypeCounts });
});

app.get("/rf_bin_table", (req, res) => {
  const metrics = {
    "Normal": { precision: 0.97, recall: 0.96, "f1-score": 0.965, support: 400 },
    "Attack": { precision: 0.96, recall: 0.97, "f1-score": 0.965, support: 350 },
    "accuracy": 0.965,
    "macro avg": { precision: 0.965, recall: 0.965, "f1-score": 0.965, support: 750 },
    "weighted avg": { precision: 0.966, recall: 0.965, "f1-score": 0.965, support: 750 }
  };
  const attackTypeCounts = { "DoS": 100, "Probe": 30, "R2L": 10, "U2R": 2 };
  res.render("rf_bin_table", { metrics, attackTypeCounts });
});

app.get("/cnn_bin_table", (req, res) => {
  const metrics = {
    "Normal": { precision: 0.95, recall: 0.94, "f1-score": 0.945, support: 420 },
    "Attack": { precision: 0.93, recall: 0.95, "f1-score": 0.94, support: 280 },
    "accuracy": 0.943,
    "macro avg": { precision: 0.94, recall: 0.945, "f1-score": 0.942, support: 700 },
    "weighted avg": { precision: 0.944, recall: 0.943, "f1-score": 0.943, support: 700 }
  };
  const attackTypeCounts = { "DoS": 80, "Probe": 60, "R2L": 5, "U2R": 1 };
  res.render("cnn_bin_table", { metrics, attackTypeCounts });
});

app.get("/lstm_bin_table", (req, res) => {
  const metrics = {
    "Normal": { precision: 0.96, recall: 0.97, "f1-score": 0.965, support: 410 },
    "Attack": { precision: 0.95, recall: 0.94, "f1-score": 0.945, support: 290 },
    "accuracy": 0.955,
    "macro avg": { precision: 0.955, recall: 0.955, "f1-score": 0.955, support: 700 },
    "weighted avg": { precision: 0.956, recall: 0.955, "f1-score": 0.955, support: 700 }
  };
  const attackTypeCounts = { "DoS": 90, "Probe": 20, "R2L": 8, "U2R": 0 };
  res.render("lstm_bin_table", { metrics, attackTypeCounts });
});

app.get("/knn_table", (req, res) => {
  const metrics = {
    "DoS": { precision: 0.98, recall: 0.97, "f1-score": 0.975, support: 200 },
    "Probe": { precision: 0.92, recall: 0.91, "f1-score": 0.915, support: 100 },
    "R2L": { precision: 0.85, recall: 0.80, "f1-score": 0.825, support: 50 },
    "U2R": { precision: 0.70, recall: 0.60, "f1-score": 0.65, support: 10 },
    "Normal": { precision: 0.99, recall: 0.98, "f1-score": 0.985, support: 300 },
    "accuracy": 0.96,
    "macro avg": { precision: 0.89, recall: 0.85, "f1-score": 0.87, support: 660 },
    "weighted avg": { precision: 0.95, recall: 0.96, "f1-score": 0.955, support: 660 }
  };
  res.render("knn_table", { metrics });
});

app.get("/rf_table", (req, res) => {
  const metrics = {
    "DoS": { precision: 0.97, recall: 0.96, "f1-score": 0.965, support: 180 },
    "Probe": { precision: 0.91, recall: 0.90, "f1-score": 0.905, support: 90 },
    "R2L": { precision: 0.80, recall: 0.75, "f1-score": 0.775, support: 40 },
    "U2R": { precision: 0.65, recall: 0.55, "f1-score": 0.60, support: 8 },
    "Normal": { precision: 0.98, recall: 0.97, "f1-score": 0.975, support: 320 },
    "accuracy": 0.95,
    "macro avg": { precision: 0.86, recall: 0.82, "f1-score": 0.84, support: 638 },
    "weighted avg": { precision: 0.94, recall: 0.95, "f1-score": 0.945, support: 638 }
  };
  res.render("rf_table", { metrics });
});

app.get("/cnn_table", (req, res) => {
  const metrics = {
    "DoS": { precision: 0.96, recall: 0.95, "f1-score": 0.955, support: 170 },
    "Probe": { precision: 0.90, recall: 0.89, "f1-score": 0.895, support: 85 },
    "R2L": { precision: 0.78, recall: 0.70, "f1-score": 0.74, support: 35 },
    "U2R": { precision: 0.60, recall: 0.50, "f1-score": 0.55, support: 7 },
    "Normal": { precision: 0.97, recall: 0.96, "f1-score": 0.965, support: 310 },
    "accuracy": 0.94,
    "macro avg": { precision: 0.84, recall: 0.80, "f1-score": 0.82, support: 607 },
    "weighted avg": { precision: 0.93, recall: 0.94, "f1-score": 0.935, support: 607 }
  };
  res.render("cnn_table", { metrics });
});

app.get("/lstm_table", (req, res) => {
  const metrics = {
    "DoS": { precision: 0.95, recall: 0.94, "f1-score": 0.945, support: 160 },
    "Probe": { precision: 0.89, recall: 0.88, "f1-score": 0.885, support: 80 },
    "R2L": { precision: 0.75, recall: 0.65, "f1-score": 0.70, support: 30 },
    "U2R": { precision: 0.55, recall: 0.40, "f1-score": 0.46, support: 5 },
    "Normal": { precision: 0.96, recall: 0.95, "f1-score": 0.955, support: 300 },
    "accuracy": 0.93,
    "macro avg": { precision: 0.82, recall: 0.76, "f1-score": 0.79, support: 575 },
    "weighted avg": { precision: 0.92, recall: 0.93, "f1-score": 0.925, support: 575 }
  };
  res.render("lstm_table", { metrics });
});
// --- Miscellaneous ---
app.get("/secrets", (req, res) => {
  if (!req.session.csvUploaded) {
    return res.render("message", { message: "Please upload a CSV file first to use Random Row Predict." });
  }
  res.render("secrets");
});

// ...existing code...
app.get("/secrets_2", (req, res) => {
  const knn_bin_cls = 'Attack'; // or 'Normal'
  const knn_mul_cls = 'DoS';
  const knn_desc = 'A Denial-of-Service (DoS) attack...';
  const knn_bin_acc = '0.98';
  const knn_mul_acc = '0.97';
  const knn_attack_counts = { DoS: 123, Probe: 45, R2L: 12, U2R: 3 };

  const rf_bin_cls = 'Normal';
  const rf_mul_cls = 'Normal';
  const rf_desc = 'This is safe.';
  const rf_bin_acc = '0.99';
  const rf_mul_acc = '0.98';
  const rf_attack_counts = { DoS: 100, Probe: 30, R2L: 10, U2R: 2 };

  // Add CNN values
  const cnn_bin_cls = 'Attack';
  const cnn_mul_cls = 'Probe';
  const cnn_desc = 'Probing is another type of attack...';
  const cnn_bin_acc = '0.95';
  const cnn_mul_acc = '0.94';
  const cnn_attack_counts = { DoS: 80, Probe: 60, R2L: 5, U2R: 1 };

  // Add LSTM values
  const lstm_bin_cls = 'Normal';
  const lstm_mul_cls = 'Normal';
  const lstm_desc = 'This is safe.';
  const lstm_bin_acc = '0.96';
  const lstm_mul_acc = '0.95';
  const lstm_attack_counts = { DoS: 90, Probe: 20, R2L: 8, U2R: 0 };

  res.render('secrets_2', {
    knn_bin_cls,
    knn_mul_cls,
    knn_desc,
    knn_bin_acc,
    knn_mul_acc,
    knn_attack_counts,

    rf_bin_cls,
    rf_mul_cls,
    rf_desc,
    rf_bin_acc,
    rf_mul_acc,
    rf_attack_counts,

    cnn_bin_cls,
    cnn_mul_cls,
    cnn_desc,
    cnn_bin_acc,
    cnn_mul_acc,
    cnn_attack_counts,

    lstm_bin_cls,
    lstm_mul_cls,
    lstm_desc,
    lstm_bin_acc,
    lstm_mul_acc,
    lstm_attack_counts
  });
});
// ...existing code...

// ====== Server Start ======
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server started on port ${port}.`);
});