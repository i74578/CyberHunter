// Funtion for performing attacks and visualize it on the node or AP
function perform_attack(targetMac, mode) {
    const nodeData = nodes.get(targetMac);
    if (nodeData.color === 'OrangeRed') {
        nodeData.color = null;
        socket.emit("setMode", { 'mode': 'idle', 'target': nodeData.id });
    } else {
        nodeData.color = 'OrangeRed';
        socket.emit("setMode", { 'mode': mode, 'target': nodeData.id });
    }
    nodes.update(nodeData);
}

function deauth_attack(target_mac) {
    perform_attack(target_mac, 'deauth_attack');
}

function csa_attack(target_mac) {
    perform_attack(target_mac, 'csa_attack');
}

//Focus mechanising to focus on specific node/AP
function focusSelect(item) {
    var options = {
        scale: 1.5,
        animation: {
            duration: 1000,
            easingFunction: 'easeInOutQuad'
        },
    };
    network.unselectAll()
    network.selectNodes([item.label]);
    network.focus(item.label, options);
}

const socket = io();
var waitingForReadyState = false;

$(document).ready(function() {});

socket.on("connect", () => {
    console.log("connected");
});

socket.on("disconnect", () => {
    console.log("disconnected");
});

function setMode(mode) {
    waitingForReadyState = true;
    if (mode == "idle"){
        socket.emit("setMode", {'mode':'idle'});
    }
    else if (mode == "sniff"){
        socket.emit("setMode", {'mode':'sniff'});
    }
}

socket.on("initGraph", function(msg) {
    if (waitingForReadyState){return}
    var parsedMsg = JSON.parse(msg);
    if (parsedMsg.nodes.length == 0 && parsedMsg.edges.length == 0){
        setProgressBar("100%");
    }
    else {
        nodes = new vis.DataSet(parsedMsg.nodes);
        edges = new vis.DataSet(parsedMsg.edges);
        network.setData({nodes:nodes,edges:edges})
        let ids = parsedMsg.nodes.map(object => object.id);
        console.log(ids);
        addOptionsToDatalist(ids);
    }
});

socket.on("addToGraph", function(msg) {
    if (waitingForReadyState){return}
    var parsedMsg = JSON.parse(msg);
    nodes.add(parsedMsg.nodes);
    edges.add(parsedMsg.edges);
    let ids = parsedMsg.nodes.map(object => object.id);
    addOptionsToDatalist(ids);
});

socket.on("clearGraph", function(msg) {
    nodes.clear();
    edges.clear();
    while(dropdownMenuNodes.length > 0) {
        dropdownMenuNodes.pop();
    }
});

socket.on("modeReady", function(msg) {
    waitingForReadyState = false;
});

var datalist = document.getElementById("list-nodes");
nodes = new vis.DataSet();
edges = new vis.DataSet();
var container = document.getElementById("mynetwork");
var networkData = { nodes: nodes, edges: edges };
var options = {
    nodes: {  
        shapeProperties: {
            useImageSize: true,
            useBorderWithImage: false,
            interpolation: false,
            coordinateOrigin: "center"
        }
    },
    edges: {
         color: {  
            color: "#848484"}
    },
    interaction: {
        hover: true
    },
    groups: {
        ssid: {
            color: "HotPink",
        },
        client: {
            color: "Orange",
        },
        ap: { 
            color: "LightBlue" 
        }
    },
};

network = new vis.Network(container, networkData, options);

network.on("doubleClick", function (params) {
    if (params.nodes.length == 1 ) {
        let target_mac = params.nodes[0]
        let node_data = nodes.get(target_mac);
        // Perform standard deauth attack if client is selected
        if (node_data.group == "client"){
            deauth_attack(target_mac);
        } 
        // Perform CSA attack if AP is selected
        else if(node_data.group == "ap"){
            csa_attack(target_mac);
        } 
    }
});  

network.on("stabilizationProgress", function (params) {
    console.log("stabilizationProgress")
    var percentage = Math.round((params.iterations / params.total)*100)+"%";
    setProgressBar(percentage);

});

network.once("stabilizationIterationsDone", function () {
    setProgressBar("100%");
});

function setProgressBar(percentage){
    $(".progress-bar").css('width', percentage);
    if (percentage=="100%"){
        setTimeout(function () {
            $(".loadingOverlay").css('opacity',0);
            $(".loadingOverlay").css('display',"none");
        },1000);
    }
}

function addOptionsToDatalist(optionValue) {
    for (let i=0;i<optionValue.length;i++){
        dropdownMenuNodes.push({label:optionValue[i],value:optionValue[i]});
    }
}

dropdownMenuNodes = [{ label: "init", value: "init" }];
$('#myAutocomplete').autocomplete({
    source: dropdownMenuNodes,
    treshold: 1,
    maximumItems: 10,
    highlightClass: 'text-danger',
    dropdownClass: 'scrolled-dropdown',
    onSelectItem:focusSelect
});
