var express = require('express');
var fs = require('fs');
var app = express();
var regionMap = require('./all.json');

app.use(express.json());       // to support JSON-encoded bodies
app.use(express.urlencoded()); // to support URL-encoded bodies

app.get('/running', function(req, res){
  res.send('Totally running');
});

app.post('/what', function(req, res){
  d = new Date();
  date_string = d.toISOString();
  uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    var r = Math.random()*16|0, v = c == 'x' ? r : (r&0x3|0x8);
    return v.toString(16).toUpperCase();
  });

  incident = {'discovery_method':'Unknown',
              'schema_version':'1.3',
              'action':{'hacking':{'variety':['DoS'],'vector':['Web application']}},
              'actor':{'external':{}},
              "security_incident": "Confirmed",
              "source_id": "vcdb",
              "summary": "Denial of service attack",
              'attribute':{'availability':{'variety':['Interruption']}},
              'asset':{'assets':[]},
              'reference':"",
              'victim':{},
              'plus':{},
              'timeline':{'incident':{}}};
  incident.actor.external.variety = [req.body.actor_variety];
  incident.actor.external.motive = [req.body.actor_motive];
  incident.actor.external.country = [req.body.actor_country];
  if (req.body.actor_region !== "") {
    incident.actor.external.region = [req.body.actor_region]};
  if (req.body.actor_country !== "Unknown") {
    incident.actor.external.region = Array(regionMap[req.body.actor_country])};

  incident.timeline.incident.year = parseInt(req.body.incident_year);
  if (req.body.incident_month !== "Unknown"){
    incident.timeline.incident.month = parseInt(req.body.incident_month)};
  if (req.body.incident_day !== "Unknown"){
    incident.timeline.incident.day = parseInt(req.body.incident_day)};

  if (req.body.victim_id !== ""){
    incident.victim.victim_id = req.body.victim_id};
  incident.victim.employee_count = req.body.employee_count;
  incident.victim.country = [req.body.victim_country];
  incident.victim.industry = req.body.industry;
  if (req.body.victim_region !== "") {
    incident.victim.region = [req.body.victim_region]};
  if (req.body.victim_country !== "Unknown") {
    incident.victim.region = Array(regionMap[req.body.victim_country])};


  incident.asset.assets.push({'variety':req.body.asset_variety});

  if (typeof(req.body.source) !== "string"){
    for (i=0;i<req.body.source.length;i++){
      incident.reference += req.body.source[i] + ' (' + date_string + ');'};
  }
  else {
    incident.reference = req.body.source + ' (' + date_string + ');';
  };

  incident.plus.analysis_status = "First pass";
  incident.plus.analyst = req.body.nickname;
  incident.plus.github = req.body.github;
  incident.plus.created = date_string;
  incident.plus.modified = date_string;
  incident.plus.master_id = uuid;
  incident.incident_id = uuid;
  filename = 'responses/' + uuid + '.json';

  if (req.body.notes !== ""){
    incident.notes = req.body.notes};
  fs.appendFile(filename,JSON.stringify(incident,undefined,2)+'\n');
  res.redirect('http://vcdb.org/v2/thank.html');
});

app.post('/wrong', function(req, res){
  fs.appendFile('wrong.txt', req.body.github + " is labeled incorrectly.\n");
  res.redirect('http://vcdb.org/v2/thank.html');
});

var server = app.listen(3000, function() {
    console.log('Listening on port %d', server.address().port);
});
