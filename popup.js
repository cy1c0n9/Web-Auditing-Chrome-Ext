document.addEventListener('DOMContentLoaded',function(){
	let content=document.getElementById('content');
	content.innerHTML="";
	var dict;
	var id;
	var u=['L1H','L2H','L3H','L1P','L2P','L3P'];
	var v=[
		'Lack of use of strict-transport-security in following hosts',
		'The max-age of strict-transport-security is too short',
		'Lack of use or disabled x-xss-protection in following hosts',
		'Lack of use of content-security-policy in following hosts',
		'Lack of use of x-frame-options in following hosts',
		'Using allow-from parameter in x-frame-options may be less secure',
		'Lack of use of x-content-type-options in following hosts'
	]
	var p,q;
	// chrome.storage.sync.get('dict',function(data){
	chrome.tabs.query({ currentWindow: true, highlighted: true }, function (tabs) {
		id=tabs[0].id;
		dict=chrome.extension.getBackgroundPage().tabsInfo;
		content.innerHTML+="<h1>Security Flaws</h1>";
		if(dict[id]!=undefined)
		for(k in dict[id].securityHeaders){
			if(dict[id].securityHeaders[k].length==0) continue;
			content.innerHTML+="<hr>";
			if(k=='notHSTS') p=2,q=0;
			else if(k=='shortHSTS') p=1,q=1;
			else if(k=='notXSSPro') p=2,q=2;
			else if(k=='notCSP') p=2,q=3;
			else if(k=='notXFO') p=2,q=4;
			else if(k=='badXFO') p=0,q=5;
			else if(k=='notXCTO') p=2,q=6;
			var pp=p+1;
			content.innerHTML+='<h2 style="color:red" class="'+u[p]+'">'+'LEVEL '+pp+'  :  '+v[q]+'</h2>';
			for(i in dict[id].securityHeaders[k]){
				content.innerHTML+='<p class="'+u[p+3]+'">'+dict[id].securityHeaders[k][i]+'</p>';
			}
		}
	});
	// });
})