const requests = 4;
let progress = 0;

function updateProgressBar() {
    progress++;
    const progressBar = document.getElementById('progress-bar');
    const progressPercentage = (progress / requests) * 100;
    progressBar.style.width = `${progressPercentage}%`;

    if (progress === requests) {
        console.log('Todas las solicitudes completadas');
        enableInputFile();
        progress = 0;
    }
}

function disableInputFile()
{
    const inputElement = document.getElementById('uploadFile');
    inputElement.disabled = true;
}

function enableInputFile()
{
    const inputElement = document.getElementById('uploadFile');
    inputElement.disabled = false;
}

function startUploadFile() 
{
    
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    
    if (file) {
        const formData = new FormData(); 
        formData.append('file', file);
        
        const xhr = new XMLHttpRequest();
        xhr.open('POST', 'http://127.0.0.1:8000/file', true);
        xhr.send(formData);

        disableInputFile();
        
        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4 && xhr.status === 200) {
                console.log('Archivo enviado exitosamente.');

                try {
                    const result = JSON.parse(xhr.responseText);
                    updateProgressBar();
                    callManalyze(result);
                    callFloss(result);
                    callCapa(result);
                } catch (e) {
                    console.error('Error al analizar la respuesta JSON:', e);
                }
            }
        };
    } else {
        console.log('Selecciona un archivo antes de enviarlo.');
    }
}

function callManalyze(json_data)
{
    const xhr = new XMLHttpRequest();
    xhr.open('GET', `http://127.0.0.1:8000/manalyze?data=${json_data.data}`, true);
    xhr.send();

    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4 && xhr.status === 200) {
            console.log('Solicitud GET exitosa.');

            try {
                const result = JSON.parse(xhr.responseText);
                getManalyzeInfo(result.manalyze);
                updateProgressBar();
            } catch (e) {
                console.error('Error al analizar la respuesta JSON:', e);
            }
        }
    };
}

function callFloss(json_data)
{
    const xhr = new XMLHttpRequest();
    xhr.open('GET', `http://127.0.0.1:8000/floss?data=${json_data.data}`, true);
    xhr.send();

    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4 && xhr.status === 200) {
            console.log('Solicitud GET exitosa.');

            try {
                const result = JSON.parse(xhr.responseText);
                getFlossInfo(result.floss);
                updateProgressBar();
            } catch (e) {
                console.error('Error al analizar la respuesta JSON:', e);
            }
        }
    };
}

function callCapa(json_data)
{
    const xhr = new XMLHttpRequest();
    xhr.open('GET', `http://127.0.0.1:8000/capa?data=${json_data.data}`, true);
    xhr.send();

    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4 && xhr.status === 200) {
            console.log('Solicitud GET exitosa.');

            try {
                const result = JSON.parse(xhr.responseText);
                getCapaInfo(result.capa);
                updateProgressBar();
            } catch (e) {
                console.error('Error al analizar la respuesta JSON:', e);
            }
        }
    };
}

function getCapaInfo(capa)
{
    const meta = capa.meta;

    let analysis = meta.analysis;
    delete analysis.feature_counts;
    delete analysis.layout;
    
    createHTML2(analysis, 'html_analysis');
    createHTML(meta.sample, 'html_sample');
    createHTMLRules(capa.rules, 'html_rules')
}

function getFlossInfo(floss)
{
    const strings = floss.strings;

    const decoded_count = strings.decoded_strings.length;
    const stack_count = strings.stack_strings.length;
    const static_count = strings.static_strings.length;
    const tight_count = strings.tight_strings.length;

    createHTML3(strings.decoded_strings, "html_decoded");
    createHTML3(strings.tight_strings, "html_tight");
    createHTML3(strings.stack_strings, "html_stack");
    createHTML3(strings.static_strings, "html_static");

    document.getElementById("decoded_text").textContent = decoded_count;
    document.getElementById("stack_text").textContent = stack_count;
    document.getElementById("static_text").textContent = static_count;
    document.getElementById("tight_text").textContent = tight_count;
}

function getManalyzeInfo(manalyze)
{
    const pe_files = Object.entries(manalyze);

    const name_file = pe_files[0][0];
    let current_pe_file = pe_files[0][1];

    let html_name = document.getElementById("file_name");
    html_name.textContent = "File : "  + name_file;

    getImports(current_pe_file.Imports);
    createHTML(current_pe_file.Hashes,'html_hashes');
    createHTML(current_pe_file.Summary,'html_summaries');
    createHTML(current_pe_file["DOS Header"],'html_dos_headers');
    createHTML(current_pe_file["Image Optional Header"],'html_image');
    createHTML(current_pe_file["PE Header"],'html_pe_header');
    createHTML(current_pe_file["TLS Callbacks"],'html_tls');
    createHTML2(current_pe_file["Sections"],'html_sections');
}

function getImports(imports)
{
    const imports_values = Object.entries(imports);

    imports_values.forEach((dll, index_dll) => {

        const name_dll = dll[0];

        getImportDLL(dll[1],name_dll, index_dll);
 
    });
}

function getImportDLL(import_dll, name_dll, index_dll)
{
    const html_element = document.getElementById('html_imports');
    let html_code = html_element.innerHTML;
    html_code += '<h6 class="card-title">' + name_dll + '</h6>';
    html_element.innerHTML = html_code;

    createHTML(import_dll,'html_imports', index_dll);
    
}


function createHTML(objectData, elementId, index)
{
    if(!checkArrayNullOrEmpty(objectData))
    {
        return ;
    }

    const html_element = document.getElementById(elementId);

    let html_code = html_element.innerHTML;

    const table_name = elementId+"_table"+ ( index != null ? index : "");

    html_code += '<table id="' + table_name  + '" class="table table-sm">';
    html_code +=    '<thead>';
    html_code +=        '<tr>';
    html_code +=            '<th scope="col">Attribute</th>';
    html_code +=            '<th scope="col">Value</th>';
    html_code +=        '</tr>';
    html_code +=    '</thead>';
    html_code +=    '<tbody>';

    html_code += createTRs(objectData);

    html_code +=    '</tbody>';
    html_code += '</table>';

    html_element.innerHTML = html_code;
    $('#' + table_name).DataTable();
}

function createHTML2(objectData, elementId)
{
    if(!checkArrayNullOrEmpty(objectData))
    {
        return ;
    }

    const html_element = document.getElementById(elementId);

    let html_code = html_element.innerHTML;

    const table_name = elementId+"_table";

    html_code += '<table id="' + table_name + '" class="table table-sm">';
    html_code +=    '<thead>';
    html_code +=        '<tr>';
    html_code +=            '<th scope="col">Attribute</th>';
    html_code +=            '<th scope="col">Subattribute</th>';
    html_code +=            '<th scope="col">Value</th>';
    html_code +=        '</tr>';
    html_code +=    '</thead>';
    html_code +=    '<tbody>';

    html_code += createTRs2(objectData);

    html_code +=    '</tbody>';
    html_code += '</table>';

    html_element.innerHTML = html_code;
    $('#' + table_name).DataTable();
}

function createTRs(object)
{
    if(!checkArrayNullOrEmpty(object))
    {
        return ;
    }

    let html_code = "";
    const list_data = Object.keys(object);

    list_data.forEach(data => {

        let value = object[data];

        if (Array.isArray(value))
        {
            value.forEach((v, count) => {
                html_code +=        '<tr>';
                html_code +=            '<td>' + ((count === 0) ? data : "") + '</td>';
                html_code +=            '<td>' + v + '</td>';
                html_code +=        '</tr>';
            })       
        }
        else 
        {

            html_code +=        '<tr>';
            html_code +=            '<td>' + data + '</td>';
            html_code +=            '<td>' + value + '</td>';
            html_code +=        '</tr>';
        }
 
    });

    return html_code;
}

function createTRs2(object)
{
    if(!checkArrayNullOrEmpty(object))
    {
        return ;
    }

    let html_code = "";
    const list_data = Object.keys(object);

    list_data.forEach(data => {

        let value_object = object[data];

        if(typeof value_object !== "object" && !Array.isArray(value_object))
        {
            html_code +=        '<tr>';
            html_code +=            '<td>' +  data + '</td>';
            html_code +=            '<td></td>';
            html_code +=            '<td>' + value_object + '</td>';
            html_code +=        '</tr>';
        }
        else 
        {

            const list_data2 = Object.keys(value_object);

            list_data2.forEach((key2, count) => {
                let value2 = value_object[key2];

                if (Array.isArray(value2))
                {
                    value2.forEach((v, count2) => {
                        html_code +=        '<tr>';
                        html_code +=            '<td>' + ((count === 0) ? data : "") + '</td>';
                        html_code +=            '<td>' + ((count2 === 0) ? key2 : "") + '</td>';
                        html_code +=            '<td>' + v + '</td>';
                        html_code +=        '</tr>';   
                    })    
                }
                else 
                {
                    html_code +=        '<tr>';
                    html_code +=            '<td>' + ((count === 0) ? data : "") + '</td>';
                    html_code +=            '<td>' + key2 + '</td>';
                    html_code +=            '<td>' + value2 + '</td>';
                    html_code +=        '</tr>';
                }
            });
        }
    });

    return html_code;
}

function createHTML3(objectData, elementId)
{
    if(!checkArrayNullOrEmpty(objectData))
    {
        return ;
    }

    const html_element = document.getElementById(elementId);
    const keys = Object.keys(objectData[0])

    let html_code = html_element.innerHTML;

    const table_name = elementId+"_table"

    html_code += '<table id="' + table_name + '" class="table table-sm">';
    html_code +=    '<thead>';
    html_code +=        '<tr>';
    keys.forEach(key => html_code += '<th scope="col">' + key + '</th>');
    html_code +=        '</tr>';
    html_code +=    '</thead>';
    html_code +=    '<tbody>';

    objectData.forEach(obj => {
        html_code +=        '<tr>';
        keys.forEach(key => html_code += '<td>' + obj[key] + '</td>');
        html_code +=        '</tr>';
    });

    html_code +=    '</tbody>';
    html_code += '</table>';

    html_element.innerHTML = html_code;
    $('#' + table_name).DataTable();
}

function checkArrayNullOrEmpty(obj) {

    if (obj === null || typeof obj === 'undefined') {
      return false;
    }
  

    if (Array.isArray(obj) && obj.length === 0) {
      return false;
    }

    return true;
}

function createHTMLRules(rules, elementId)
{
    const html_element = document.getElementById(elementId);

    const rules_list = Object.keys(rules);

    let html_code = html_element.innerHTML;

    const table_name = elementId+"_table"

    html_code += '<table id="' + table_name + '" class="table table-sm">';
        html_code +=    '<thead>';
        html_code +=        '<tr>';
        html_code +=            '<td>Rule</td>';
        html_code +=            '<td>Attribute</td>';
        html_code +=            '<td>SubAttribute</td>';
        html_code +=            '<td>Value</td>';
        html_code +=        '</tr>';
        html_code +=    '</thead>';
        html_code +=    '<tbody>';

    rules_list.forEach(rule => {
        const meta = rules[rule].meta;
        const matches = rules[rule].matches.length;
        const attack_list = meta.attack;
        const mbc_list = meta.mbc;

        html_code +=        '<tr>';
        html_code +=        '<td>' + rule + '</td>';
        html_code +=        '<td> matches </td>';
        html_code +=        '<td> </td>';
        html_code +=        '<td>' + matches + '</td>';
        html_code +=        '</tr>';

        if(attack_list.length>0)
        {
            const attack_attributes = Object.keys(attack_list[0]);

            attack_list.forEach((attack, count) => {
                attack_attributes.forEach(attack_key => {
                    html_code +=        '<tr>';
                    html_code +=        '<td> </td>';
                    html_code +=        '<td>' + ((count === 0) ? "attack" : "") + '</td>';
                    html_code +=        '<td>' + attack_key + '</td>';
                    html_code +=        '<td>' + attack[attack_key] + '</td>';
                    html_code +=        '</tr>';
                })
            });
        }

        if(mbc_list.length>0)
        {
            const mbc_attributes = Object.keys(mbc_list[0]);

            mbc_list.forEach((mbc, count) => {
                mbc_attributes.forEach(mbc_key => {
                    html_code +=        '<tr>';
                    html_code +=        '<td> </td>';
                    html_code +=        '<td>' + ((count === 0) ? "attack" : "") + '</td>';
                    html_code +=        '<td>' + mbc_key + '</td>';
                    html_code +=        '<td>' + mbc[mbc_key] + '</td>';
                    html_code +=        '</tr>';
                })
            });
        }
    });
        

    html_code +=    '</tbody>';
    html_code += '</table>';

    html_element.innerHTML = html_code;
    $('#' + table_name).DataTable();
}