var express = require('express');
var fs = require('fs');
var app = express();
var regionMap = require('./all.json');

app.use(express.json());       // to support JSON-encoded bodies
app.use(express.urlencoded()); // to support URL-encoded bodies

app.get('/running', function(req, res){
  res.send('Totally running');
});

app.post('/deface', function(req, res){
  console.log('Incoming defacement incident.');
  d = new Date();
  date_string = d.toISOString();
  uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    var r = Math.random()*16|0, v = c == 'x' ? r : (r&0x3|0x8);
    return v.toString(16).toUpperCase();
  });
  
  incident = {'discovery_method':'Unknown',
              'schema_version':'1.3',
              'action':{'hacking':{'variety':[],'vector':[]}},
              'actor':{'external':{}},
              'security_incident':'Confirmed',
              'source_id':'vcdb',
              'summary':'Web site defacement',
              'attribute':{'integrity':{'variety':['Defacement']}},
              'asset':{'assets':[{'variety':'S - Web application'}]},
              'reference':'',
              'victim':{},
              'plus':{},
              'timeline':{'incident':{}}};
  // Action information
  if (req.body.how == "unknown") {
    incident.action.hacking.variety = Array("Unknown");
    incident.action.hacking.vector = Array("Unknown");};
  if (req.body.how == "DNS") {
    incident.action.hacking.variety = Array("Unknown");
    incident.action.hacking.vector = Array("Unknown");
    incident.asset.assets.push({'variety':'S - DNS'});
    incident.attribute.availability = {'variety':['Interruption']}; };
  if (req.body.how == "vuln") {
    incident.action.hacking.variety = Array("Other");
    incident.action.hacking.vector = Array("Web application"); };
  if (req.body.how == "sqli") {
    incident.action.hacking.variety = Array("SQLi");
    incident.action.hacking.vector = Array("Web application");
    incident.attribute.integrity.variety.push("Repurpose"); };
  if (req.body.how == "brute") {
    incident.action.hacking.variety = Array('Use of stolen creds','Brute force');
    incident.action.hacking.vector = Array("Unknown"); };
  // Actor information
  if (req.body.actor_name !== "") {
    incident.actor.external.name = Array(req.body.actor_name)};
  incident.actor.external.variety = [req.body.actor_variety];
  incident.actor.external.motive = [req.body.actor_motive];
  incident.actor.external.country = [req.body.actor_country];
  if (req.body.actor_region !== "") {
    incident.actor.external.region = [req.body.actor_region]};
  if (req.body.actor_country !== "Unknown") {
    incident.actor.external.region = Array(regionMap[req.body.actor_country])};
  
  // Victim information
  if (req.body.victim_id !== ""){
    incident.victim.victim_id = req.body.victim_id};
  incident.victim.employee_count = req.body.employee_count;
  incident.victim.country = Array(req.body.victim_country);
  incident.victim.industry = req.body.industry;
  if (req.body.victim_region !== "") {
    incident.victim.region = Array(req.body.victim_region)};
  if (req.body.victim_country !== "Unknown") {
    incident.victim.region = Array(regionMap[req.body.victim_country])};
  
  // Timeline data
  incident.timeline.incident.year = parseInt(req.body.incident_year);
  if (req.body.incident_month !== "Unknown"){
    incident.timeline.incident.month = parseInt(req.body.incident_month)};
  if (req.body.incident_day !== "Unknown"){
    incident.timeline.incident.day = parseInt(req.body.incident_day)};
  
  // Metadata
  incident.plus.analysis_status = "First pass";
  incident.plus.analyst = req.body.nickname;
  incident.plus.github = req.body.github;
  incident.plus.created = date_string;
  incident.plus.modified = date_string;
  incident.plus.master_id = uuid;
  incident.incident_id = uuid;
  if (typeof(req.body.source) !== "string"){
    for (i=0;i<req.body.source.length;i++){
      incident.reference += req.body.source[i] + ' (' + date_string + ');'};
  }
  else {
    incident.reference = req.body.source + ' (' + date_string + ');';
  };
  if (req.body.notes !== ""){
    incident.notes = req.body.notes};
  
  // Write the output file
  filename = 'responses/' + uuid + '.json';
  fs.appendFile(filename,JSON.stringify(incident,undefined,2)+'\n');
  
  // Redirect the user and thank them
  res.redirect('http://vcdb.org/v2/thank.html');
});

app.post('/what', function(req, res){
  console.log('Incoming denial of service incident.');
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
  console.log('someone reported that ' + req.body.github + ' is labeled wrongly.');
  fs.appendFile('wrong.txt', req.body.github + " is labeled incorrectly.\n");
  res.redirect('http://vcdb.org/v2/thankulongtime.html');
});

var server = app.listen(3000, function() {
    console.log('Listening on port %d', server.address().port);
});
