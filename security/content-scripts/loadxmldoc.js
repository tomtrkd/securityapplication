function loadXMLDoc(filename)
			{
			if (window.XMLHttpRequest)
			{
			xhttp=new XMLHttpRequest();
			}
			else
			{
			xhttp=new ActiveXObject("http://192.168.50.251:5000/");
			}
			xhttp.open("GET",Filename,false);
			xhttp.send();
			return xhttp.responseXML;
			}
