function dropdownMenu(){
    var a = document.getElementById('menu');
    if(a.className == 'menu_'){
        a.className += ' show'
    }
    else{
        a.className = 'menu_'
    }
}
