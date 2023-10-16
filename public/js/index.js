let static_detail = null;

document.getElementById('uploadForm').addEventListener('submit', function(e) {
    e.preventDefault(); 
    
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    
    if (file) {
        const formData = new FormData(); 
        formData.append('file', file);
        
        const xhr = new XMLHttpRequest();
        xhr.open('POST', 'http://127.0.0.1:8000/flare', true);
        xhr.send(formData);
        
        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4 && xhr.status === 200) {
                console.log('Archivo enviado exitosamente.');

                try {
                    static_detail = JSON.parse(xhr.responseText);
                    getManalyzerInfo();

                } catch (e) {
                    console.error('Error al analizar la respuesta JSON:', e);
                }
            }
        };
    } else {
        console.log('Selecciona un archivo antes de enviarlo.');
    }
});

function getManalyzerInfo()
{
    let manalyze = static_detail.manalyze;
    const pe_files = Object.entries(manalyze);

    const name_file = pe_files[0][0];
    let current_pe_file = pe_files[0][1];

    let html_name = document.getElementById("file_name");
    html_name.textContent = name_file;

    getDOS(current_pe_file["DOS Header"]);
    getHashes(current_pe_file.Hashes);
    getSummaries(current_pe_file.Summary);
    getImports(current_pe_file.Imports);
    getImageOpcionalHeader(current_pe_file["Image Optional Header"]);
    getPEHeader(current_pe_file["PE Header"]);
    getTLSCallbacks(current_pe_file["TLS Callbacks"]);
    getSections(current_pe_file["Sections"]);
}

function getImports(imports)
{
    const imports_values = Object.entries(imports);

    imports_values.forEach(dll => {

        const name_dll = dll[0];

        getImportDLL(dll[1],name_dll);
 
    });
}

function getImportDLL(import_dll, name_dll)
{
    const html_element = document.getElementById('html_imports');
    let html_code = html_element.innerHTML;
    html_code += '<h6 class="card-title">' + name_dll + '</h6>';
    html_element.innerHTML = html_code;

    createHTML(import_dll,'html_imports');
    
}

function getHashes(hashes)
{
    createHTML(hashes,'html_hashes');
}

function getSummaries(summaries)
{
    createHTML(summaries,'html_summaries');
}

function getDOS(dosHeaders)
{
    createHTML(dosHeaders,'html_dos_headers');
}

function getImageOpcionalHeader(images)
{
    createHTML(images,'html_image');
}

function getPEHeader(peHeaders)
{
    createHTML(peHeaders,'html_pe_header');
}

function getTLSCallbacks(tls)
{
    createHTML(tls,'html_tls');
}

function getSections(sections)
{
    createHTML2(sections,'html_sections');
}

function createHTML(objectData, elementId)
{
    const html_element = document.getElementById(elementId);

    let html_code = html_element.innerHTML;

    html_code += '<table class="table table-sm">';
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
}

function createHTML2(objectData, elementId)
{
    const html_element = document.getElementById(elementId);

    let html_code = html_element.innerHTML;

    html_code += '<table class="table table-sm">';
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
}

function createTRs(object)
{
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
    let html_code = "";
    const list_data = Object.keys(object);

    list_data.forEach(data => {

        let value_object = object[data];

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
    });

    return html_code;
}
