const config = require('./config')();
const functions = require('firebase-functions');
const admin = require('firebase-admin');
admin.initializeApp(functions.config().firebase);
 
const db = admin.firestore();
const cors = require('cors')({origin: true});
const crypto = require('crypto');
const deToken = (token) => {
  try {
    token = token.split('.')[1];
    const nowDate = new Date();
    const longTime = nowDate.getTime();

    const decipher = crypto.createDecipher('aes-256-cbc', config.SECRET_KEY); 
    let tokenString = decipher.update(token, 'base64', 'utf8');
    tokenString += decipher.final('utf8');

    const userData = tokenString.split('/pw/');
    const id = userData[0];
    const pw = userData[1].split('/time/')[0];
    const time = userData[1].split('/time/')[1];
    if(!Number(time) || longTime > Number(time)) return false;
    return {id, pw};
  } catch(e) {
    return false;
  }
};

exports.login = functions.https.onRequest((req, res) => {
  cors(req, res, () => {
    const nowDate = new Date();
    const longTime = nowDate.getTime();
    const id = req.body.id;
    const pw = req.body.pw;
    if(!id || !pw) return res.status(200).send({error: '아이디 또는 비밀번호를 입력하지 않았습니다.'});
    const tokenData = id + '/pw/' + pw + '/time/' + (longTime + 604800000);
    const cipher = crypto.createCipher('aes-256-cbc', config.SECRET_KEY); 
    let token = cipher.update(tokenData, 'utf8', 'base64');
    token += cipher.final('base64');
    token = id + '.' + token;
    return res.status(200).send({error: null, token});
  });
})


exports.getSecretNote = functions.https.onRequest((req, res) => {
  cors(req, res, () => {
    const token = req.get('token');
    const userData = deToken(token);
    if(!userData) return res.status(200).send({error : '로그인 세션이 만료되었습니다.'});

    crypto.pbkdf2(userData.pw, config.SECRET_KEY, config.ROOP_LENGTH, config.PASSWORD_SIZE, config.ALGORITHM, (err, key) => {
      if(err) console.log(err.stack);
      const encPassword = key.toString('base64');
      db.collection('secret').doc(userData.id).collection('note').where('password', '==', encPassword)
      .get().then(snapshot => {
        let textDataMemo = [];
        let textDataGroup = [];
        let options = null;
        snapshot.forEach(doc => {
          const dataMemos = doc.data().dataMemos;
          for(let i in dataMemos) {
            textDataMemo[i] = [];
            for(let j=0; j<dataMemos[i].length; j++) {
              const cipher = crypto.createDecipher('aes-256-cbc', userData.pw);
              let textVal = cipher.update(dataMemos[i][j], 'base64', 'utf8');
              textVal += cipher.final('utf8');
              textDataMemo[i].push(textVal);
            }
          }
          textDataGroup = doc.data().dataGroups;
          options = doc.data().options;
        });
        const nowDate = new Date();
        const longTime = nowDate.getTime();
        return res.status(200).send({ textDataGroup, textDataMemo, options, longTime, time: userData.time });
      }).catch(err => console.log('Error', err));
    });
  });
});

exports.updateSecretNote = functions.https.onRequest((req, res) => {
  cors(req, res, () => {
    const token = req.get('token');
    const userData = deToken(token);
    const dataGroups = req.body.dataGroups;
    const dataMemos = req.body.dataMemos;
    const options = req.body.options;

    if(!userData) return res.status(200).send({error : '로그인 세션이 만료되었습니다.'});
    crypto.pbkdf2(userData.pw, config.SECRET_KEY, config.ROOP_LENGTH, config.PASSWORD_SIZE, config.ALGORITHM, (err, key) => {
      if(err) console.log(err.stack);
      const encPassword = key.toString('base64');

      let encMemos = {};
      for(let i=0; i<dataMemos.length; i++) {
        encMemos[i] = [];
        for(let j=0; j<dataMemos[i].length; j++) {
          const cipher = crypto.createCipher('aes-256-cbc', userData.pw);
          let encTextVal = cipher.update(dataMemos[i][j], 'utf8', 'base64');
          encTextVal += cipher.final('base64');
          encMemos[i].push(encTextVal);
        }
      }
      
      db.collection('secret').doc(userData.id).collection('note').where('password', '==', encPassword)
      .get().then(snapshot => {

        db.collection('secret').doc(userData.id).collection('note').doc().onSnapshot(doc => {
          return res.status(200).send();
        });

        if(snapshot.empty) {
          db.collection('secret').doc(userData.id).collection('note').doc().set({ 
            password: encPassword,
            dataGroups: dataGroups,
            dataMemos: encMemos,
            options: options
          });
        } else {
          snapshot.forEach(doc => {
            db.collection('secret').doc(userData.id).collection('note').doc(doc.id).update({ 
              dataGroups: dataGroups,
              dataMemos: encMemos,
              options: options
            });
          });
        }
        return;
      }).catch(err => console.log('Error', err));
    });
  });
});